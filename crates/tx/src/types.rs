use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::hash::Hash;
use std::io;
use std::ops::{Bound, RangeBounds};
use std::str::FromStr;

use masp_primitives::transaction::Transaction;
use namada_account::AccountPublicKeysMap;
use namada_core::address::Address;
use namada_core::borsh::{
    self, BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
};
use namada_core::chain::{BlockHeight, ChainId};
use namada_core::collections::{HashMap, HashSet};
use namada_core::key::*;
use namada_core::masp::MaspTxId;
use namada_core::storage::TxIndex;
use namada_core::time::DateTimeUtc;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::data::{Fee, GasLimit, TxType, WrapperTx};
use crate::sign::{SignatureIndex, VerifySigError};
use crate::{
    Authorization, Code, Data, Header, MaspBuilder, Section, Signer,
    TxCommitments, proto,
};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Invalid signature index bytes: {0}")]
    InvalidEncoding(std::io::Error),
    #[error("Invalid signature index: {0}")]
    InvalidHex(data_encoding::DecodeError),
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(prost::DecodeError),
    #[error("Timestamp is empty")]
    NoTimestampError,
    #[error("Timestamp is invalid: {0}")]
    InvalidTimestamp(prost_types::TimestampError),
    #[error("Couldn't serialize transaction from JSON at {0}")]
    InvalidJSONDeserialization(String),
}

#[allow(missing_docs)]
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum TxError {
    #[error("{0}")]
    Unsigned(String),
    #[error("{0}")]
    SigError(String),
    #[error("Failed to deserialize Tx: {0}")]
    Deserialization(String),
    #[error("Tx contains repeated sections")]
    RepeatedSections,
}

/// A Namada transaction is represented as a header followed by a series of
/// sections providing additional details.
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
pub struct Tx {
    /// Type indicating how to process transaction
    pub header: Header,
    /// Additional details necessary to process transaction
    pub sections: Vec<Section>,
}

/// Deserialize Tx from protobufs
impl TryFrom<&[u8]> for Tx {
    type Error = DecodeError;

    fn try_from(tx_bytes: &[u8]) -> Result<Self, DecodeError> {
        Tx::try_from_bytes(tx_bytes)
    }
}

impl Default for Tx {
    fn default() -> Self {
        Self {
            header: Header::new(TxType::Raw),
            sections: vec![],
        }
    }
}

impl Tx {
    /// Initialize a new transaction builder
    pub fn new(chain_id: ChainId, expiration: Option<DateTimeUtc>) -> Self {
        Tx {
            sections: vec![],
            header: Header {
                chain_id,
                expiration,
                ..Header::new(TxType::Raw)
            },
        }
    }

    /// Create a transaction of the given type
    pub fn from_type(header: TxType) -> Self {
        Tx {
            header: Header::new(header),
            sections: vec![],
        }
    }

    /// Serialize tx to pretty JSON into an I/O stream
    ///
    /// For protobuf encoding, see `to_bytes/try_to_bytes`.
    pub fn to_writer_json<W>(&self, writer: W) -> serde_json::Result<()>
    where
        W: io::Write,
    {
        serde_json::to_writer_pretty(writer, self)
    }

    /// Deserialize tx from JSON string bytes
    ///
    /// For protobuf decoding, see `try_from_bytes`.
    pub fn try_from_json_bytes(data: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice::<Tx>(data)
    }

    /// Add new default commitments to the transaction. Returns false if the
    /// commitment is already contained in the set
    #[cfg(any(test, feature = "testing"))]
    pub fn push_default_inner_tx(&mut self) -> bool {
        self.header.batch.insert(TxCommitments::default())
    }

    /// Add a new inner tx to the transaction. Returns `false` if the
    /// commitments already existed in the collection. This function expects a
    /// transaction carrying a single inner tx as input and the provided
    /// commitment is assumed to be present in the transaction without further
    /// validation
    pub fn add_inner_tx(&mut self, other: Tx, mut cmt: TxCommitments) -> bool {
        if self.header.batch.contains(&cmt) {
            return false;
        }

        for section in other.sections {
            // PartialEq implementation of Section relies on an implementation
            // on the inner types that doesn't account for the possible salt
            // which is the correct behavior for this logic
            if let Some(duplicate) =
                self.sections.iter().find(|&sec| sec == &section)
            {
                // Avoid pushing a duplicated section. Adjust the commitment of
                // this inner tx for the different section's salt if needed
                match duplicate {
                    Section::Code(_) => {
                        if cmt.code_hash == section.get_hash() {
                            cmt.code_hash = duplicate.get_hash();
                        }
                    }
                    Section::Data(_) => {
                        if cmt.data_hash == section.get_hash() {
                            cmt.data_hash = duplicate.get_hash();
                        }
                    }
                    Section::ExtraData(_) => {
                        if cmt.memo_hash == section.get_hash() {
                            cmt.memo_hash = duplicate.get_hash();
                        }
                    }
                    // Other sections don't have a direct commitment in the
                    // header
                    _ => (),
                }
            } else {
                self.sections.push(section);
            }
        }

        self.header.batch.insert(cmt)
    }

    /// Remove duplicated sections from the transaction
    pub fn prune_duplicated_sections(&mut self) {
        let sections = std::mem::take(&mut self.sections);
        let mut unique_sections = HashMap::with_capacity(sections.len());
        for section in sections {
            unique_sections.insert(section.get_hash(), section);
        }

        self.sections = unique_sections.into_values().collect();
    }

    /// Get the transaction header
    pub fn header(&self) -> Header {
        self.header.clone()
    }

    /// Get the transaction's wrapper hash
    pub fn wrapper_hash(&self) -> Option<namada_core::hash::Hash> {
        matches!(&self.header.tx_type, TxType::Wrapper(_))
            .then(|| self.header_hash())
    }

    /// Get the transaction header hash
    pub fn header_hash(&self) -> namada_core::hash::Hash {
        Section::Header(self.header.clone()).get_hash()
    }

    /// Gets the hash of the raw transaction's header
    pub fn raw_header_hash(&self) -> namada_core::hash::Hash {
        let mut raw_header = self.header();
        raw_header.tx_type = TxType::Raw;

        Section::Header(raw_header).get_hash()
    }

    /// Get hashes of all the sections in this transaction
    pub fn sechashes(&self) -> Vec<namada_core::hash::Hash> {
        let mut hashes =
            Vec::with_capacity(self.sections.len().saturating_add(1));
        hashes.push(self.header_hash());
        for sec in &self.sections {
            hashes.push(sec.get_hash());
        }
        hashes
    }

    /// Get unique hashes of all the sections in this transaction
    pub fn unique_sechashes(&self) -> HashSet<namada_core::hash::Hash> {
        let mut hashes =
            HashSet::with_capacity(self.sections.len().saturating_add(1));
        hashes.insert(self.header_hash());
        for sec in &self.sections {
            hashes.insert(sec.get_hash());
        }
        hashes
    }

    /// Update the header whilst maintaining existing cross-references
    pub fn update_header(&mut self, tx_type: TxType) -> &mut Self {
        self.header.tx_type = tx_type;
        self
    }

    /// Get the transaction section with the given hash
    pub fn get_section(
        &self,
        hash: &namada_core::hash::Hash,
    ) -> Option<Cow<'_, Section>> {
        if self.header_hash() == *hash {
            return Some(Cow::Owned(Section::Header(self.header.clone())));
        } else if self.raw_header_hash() == *hash {
            let mut header = self.header();
            header.tx_type = TxType::Raw;
            return Some(Cow::Owned(Section::Header(header)));
        }
        for section in &self.sections {
            if section.get_hash() == *hash {
                return Some(Cow::Borrowed(section));
            }
        }
        None
    }

    /// Get the transaction section with the given hash
    pub fn get_masp_section(&self, hash: &MaspTxId) -> Option<&Transaction> {
        for section in &self.sections {
            if let Section::MaspTx(masp) = section {
                if MaspTxId::from(masp.txid()) == *hash {
                    return Some(masp);
                }
            }
        }
        None
    }

    /// Remove the transaction section with the given hash
    pub fn remove_masp_section(&mut self, hash: &MaspTxId) {
        self.sections.retain(|section| {
            if let Section::MaspTx(masp) = section {
                if MaspTxId::from(masp.txid()) == *hash {
                    return false;
                }
            }
            true
        });
    }

    /// Get the section containing the MASP sustainability fee payer
    /// if it exists. There should be at most one for a given MASP tx
    pub fn get_masp_sus_fee_section(
        &self,
        masp_tx: &MaspTxId,
    ) -> Option<(&common::PublicKey, &Address)> {
        for section in &self.sections {
            if let Section::MaspSustainabilityFee { payer, token, cmt } =
                section
            {
                if cmt == masp_tx {
                    return Some((payer, token));
                }
            }
        }
        None
    }

    /// Get the MASP builder section with the given hash
    pub fn get_masp_builder(&self, hash: &MaspTxId) -> Option<&MaspBuilder> {
        for section in &self.sections {
            if let Section::MaspBuilder(builder) = section {
                if builder.target == *hash {
                    return Some(builder);
                }
            }
        }
        None
    }

    /// Set the last transaction memo hash stored in the header
    pub fn set_memo_sechash(&mut self, hash: namada_core::hash::Hash) {
        let item = match self.header.batch.pop() {
            Some(mut last) => {
                last.memo_hash = hash;
                last
            }
            None => TxCommitments {
                memo_hash: hash,
                ..Default::default()
            },
        };

        self.header.batch.insert(item);
    }

    /// Get the memo designated by the memo hash in the header for the specified
    /// commitment
    pub fn memo(&self, cmt: &TxCommitments) -> Option<Vec<u8>> {
        if cmt.memo_hash == namada_core::hash::Hash::default() {
            return None;
        }

        match self.get_section(&cmt.memo_hash).as_ref().map(Cow::as_ref) {
            Some(Section::ExtraData(section)) => section.code.id(),
            _ => None,
        }
    }

    /// Add a new section to the transaction
    pub fn add_section(&mut self, section: Section) -> &mut Section {
        self.sections.push(section);
        self.sections.last_mut().unwrap()
    }

    /// Set the last transaction code hash stored in the header
    pub fn set_code_sechash(&mut self, hash: namada_core::hash::Hash) {
        let item = match self.header.batch.pop() {
            Some(mut last) => {
                last.code_hash = hash;
                last
            }
            None => TxCommitments {
                code_hash: hash,
                ..Default::default()
            },
        };

        self.header.batch.insert(item);
    }

    /// Get the code designated by the transaction code hash in the header for
    /// the specified commitment
    pub fn code(&self, cmt: &TxCommitments) -> Option<Vec<u8>> {
        match self.get_section(&cmt.code_hash).as_ref().map(Cow::as_ref) {
            Some(Section::Code(section)) => section.code.id(),
            _ => None,
        }
    }

    /// Add the given code to the transaction and set code hash in the header
    pub fn set_code(&mut self, code: Code) -> &mut Section {
        let sec = Section::Code(code);
        self.set_code_sechash(sec.get_hash());
        self.sections.push(sec);
        self.sections.last_mut().unwrap()
    }

    /// Set the last transaction data hash stored in the header
    pub fn set_data_sechash(&mut self, hash: namada_core::hash::Hash) {
        let item = match self.header.batch.pop() {
            Some(mut last) => {
                last.data_hash = hash;
                last
            }
            None => TxCommitments {
                data_hash: hash,
                ..Default::default()
            },
        };

        self.header.batch.insert(item);
    }

    /// Add the given code to the transaction and set the hash in the header
    pub fn set_data(&mut self, data: Data) -> &mut Section {
        let sec = Section::Data(data);
        self.set_data_sechash(sec.get_hash());
        self.sections.push(sec);
        self.sections.last_mut().unwrap()
    }

    /// Get the data designated by the transaction data hash in the header at
    /// the specified commitment
    pub fn data(&self, cmt: &TxCommitments) -> Option<Vec<u8>> {
        self.get_data_section(&cmt.data_hash)
    }

    /// Get the data designated by the transaction data hash
    pub fn get_data_section(
        &self,
        data_hash: &namada_core::hash::Hash,
    ) -> Option<Vec<u8>> {
        match self.get_section(data_hash).as_ref().map(Cow::as_ref) {
            Some(Section::Data(data)) => Some(data.data.clone()),
            _ => None,
        }
    }

    /// Convert this transaction into protobufs bytes.
    ///
    /// For JSON encoding see `to_writer_json`.
    pub fn to_bytes(&self) -> Vec<u8> {
        use prost::Message;

        let mut bytes = vec![];
        let tx: proto::Tx = proto::Tx {
            data: self.serialize_to_vec(),
        };
        tx.encode(&mut bytes)
            .expect("encoding a transaction failed");
        bytes
    }

    /// Convert this transaction into protobufs bytes
    ///
    /// For JSON encoding see `to_writer_json`.
    pub fn try_to_bytes(&self) -> std::io::Result<Vec<u8>> {
        use prost::Message;

        let mut bytes = vec![];
        let tx: proto::Tx = proto::Tx {
            data: borsh::to_vec(self)?,
        };
        tx.encode(&mut bytes).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        Ok(bytes)
    }

    /// Try to deserialize a tx from protobuf bytes
    ///
    /// For JSON decoding see `try_from_json_bytes`.
    pub fn try_from_bytes(tx_bytes: &[u8]) -> Result<Self, DecodeError> {
        use prost::Message;

        let tx = proto::Tx::decode(tx_bytes)
            .map_err(DecodeError::TxDecodingError)?;
        BorshDeserialize::try_from_slice(&tx.data)
            .map_err(DecodeError::InvalidEncoding)
    }

    /// Verify that the sections with the given hashes have been signed by the
    /// given public keys signatures
    pub fn verify_signatures<F>(
        &self,
        hashes: &HashSet<namada_core::hash::Hash>,
        public_keys_index_map: AccountPublicKeysMap,
        signer: &Option<Address>,
        threshold: u8,
        consume_verify_sig_gas: F,
    ) -> std::result::Result<Vec<&Authorization>, VerifySigError>
    where
        F: FnMut() -> std::result::Result<(), namada_gas::Error>,
    {
        self.verify_signatures_aux(
            hashes,
            public_keys_index_map,
            signer,
            threshold,
            consume_verify_sig_gas,
            Authorization::verify_signature::<F>,
        )
    }

    /// Same checks as [`Self::verify_signatures`] without performing the actual
    /// signature checks. Used for dry-running txs.
    pub fn dry_run_signatures<F>(
        &self,
        hashes: &HashSet<namada_core::hash::Hash>,
        public_keys_index_map: AccountPublicKeysMap,
        signer: &Option<Address>,
        threshold: u8,
        consume_verify_sig_gas: F,
    ) -> std::result::Result<Vec<&Authorization>, VerifySigError>
    where
        F: FnMut() -> std::result::Result<(), namada_gas::Error>,
    {
        self.verify_signatures_aux(
            hashes,
            public_keys_index_map,
            signer,
            threshold,
            consume_verify_sig_gas,
            Authorization::dry_run_signature::<F>,
        )
    }

    fn verify_signatures_aux<F, G>(
        &self,
        hashes: &HashSet<namada_core::hash::Hash>,
        public_keys_index_map: AccountPublicKeysMap,
        signer: &Option<Address>,
        threshold: u8,
        mut consume_verify_sig_gas: F,
        mut verifying_func: G,
    ) -> std::result::Result<Vec<&Authorization>, VerifySigError>
    where
        F: FnMut() -> std::result::Result<(), namada_gas::Error>,
        G: FnMut(
            &Authorization,
            &mut HashSet<u8>,
            &AccountPublicKeysMap,
            &Option<Address>,
            &mut F,
        ) -> std::result::Result<u8, VerifySigError>,
    {
        // Records the public key indices used in successful signatures
        let mut verified_pks = HashSet::new();
        // Records the sections instrumental in verifying signatures
        let mut witnesses = Vec::new();

        for section in &self.sections {
            if let Section::Authorization(signatures) = section {
                #[allow(clippy::disallowed_types)] // ordering doesn't matter
                let unique_targets: std::collections::HashSet<
                    &namada_core::hash::Hash,
                > = std::collections::HashSet::from_iter(
                    signatures.targets.iter(),
                );
                // Only start checking the hashes match if the number of
                // signature targets is matching
                let matching_hashes = if unique_targets.len() == hashes.len()
                    || (hashes.len() > 1
                        && unique_targets.len().saturating_add(1)
                            == hashes.len())
                {
                    let this_section_hash = section.get_hash();
                    // Check that the hashes being checked match those in
                    // this section's targets or that it's a `this_section_hash`
                    // (that cannot be included in the targets as it's a hash of
                    // itself)
                    let matching_hashes = hashes.iter().all(|x| {
                        unique_targets.contains(x) || this_section_hash == *x
                    });
                    if !matching_hashes && hashes.len() > 1 {
                        // When there is more than 1 hash (this happens for
                        // wrapper tx signature), the hashes iter should only be
                        // attempted once.
                        // We exit early as there can be only one wrapper sig,
                        // inner tx sign only over a single hash (the raw
                        // inner tx hash).
                        return Err(VerifySigError::InvalidWrapperSignature);
                    }
                    matching_hashes
                } else {
                    false
                };

                // Don't require matching hashes when fuzzing as it's unlikely
                // to be true
                #[cfg(fuzzing)]
                let _ = matching_hashes;
                #[cfg(fuzzing)]
                let matching_hashes = true;

                if matching_hashes {
                    // Finally verify that the signature itself is valid
                    let amt_verifieds = verifying_func(
                        signatures,
                        &mut verified_pks,
                        &public_keys_index_map,
                        signer,
                        &mut consume_verify_sig_gas,
                    )
                    .map_err(|_e| {
                        VerifySigError::InvalidSectionSignature(
                            "found invalid signature.".to_string(),
                        )
                    });
                    // Record the section witnessing these signatures
                    if amt_verifieds? > 0 {
                        witnesses.push(signatures);
                    }
                    // Short-circuit these checks if the threshold is exceeded
                    if verified_pks.len() >= threshold.into() {
                        return Ok(witnesses);
                    }
                }
            }
        }
        Err(VerifySigError::InvalidSectionSignature(format!(
            "signature threshold not met: ({} < {})",
            verified_pks.len(),
            threshold
        )))
    }

    /// Verify that the sections with the given hashes have been signed together
    /// by the given public key. I.e. this function looks for one signature that
    /// covers over the given slice of hashes.
    /// Note that this method doesn't consider gas cost and hence it shouldn't
    /// be used from txs or VPs.
    pub fn verify_signature(
        &self,
        public_key: &common::PublicKey,
        hashes: &HashSet<namada_core::hash::Hash>,
    ) -> Result<&Authorization, VerifySigError> {
        self.verify_signatures(
            hashes,
            AccountPublicKeysMap::from_iter([public_key.clone()]),
            &None,
            1,
            || Ok(()),
        )
        .map(|x| *x.first().unwrap())
    }

    /// Compute signatures for the given keys
    pub fn compute_section_signature(
        &self,
        secret_keys: &[common::SecretKey],
        public_keys_index_map: &AccountPublicKeysMap,
        signer: Option<Address>,
    ) -> Vec<SignatureIndex> {
        let targets = vec![self.raw_header_hash()];
        let mut signatures = Vec::new();
        let section = Authorization::new(
            targets,
            public_keys_index_map.index_secret_keys(secret_keys.to_vec()),
            signer,
        );
        match section.signer {
            Signer::Address(addr) => {
                for (idx, signature) in section.signatures {
                    signatures.push(SignatureIndex {
                        pubkey: public_keys_index_map
                            .get_public_key_from_index(idx)
                            .unwrap(),
                        index: Some((addr.clone(), idx)),
                        signature,
                    });
                }
            }
            Signer::PubKeys(pub_keys) => {
                for (idx, signature) in section.signatures {
                    signatures.push(SignatureIndex {
                        pubkey: pub_keys[idx as usize].clone(),
                        index: None,
                        signature,
                    });
                }
            }
        }
        signatures
    }

    /// Determines the type of the input Tx
    ///
    /// If it is a raw Tx, signed or not, we return `None`.
    ///
    /// If it is a WrapperTx or ProtocolTx, we extract the signed data of
    /// the Tx and verify it is of the appropriate form. This means
    /// 1. The wrapper tx is indeed signed
    /// 2. The signature is valid
    pub fn validate_tx(
        &self,
    ) -> std::result::Result<Option<&Authorization>, TxError> {
        match &self.header.tx_type {
            // verify signature and extract signed data
            TxType::Wrapper(wrapper) => {
                let hashes = self.unique_sechashes();
                if hashes.len() != self.sections.len().saturating_add(1) {
                    return Err(TxError::RepeatedSections);
                }
                self.verify_signature(&wrapper.pk, &hashes)
                    .map(Option::Some)
                    .map_err(|err| {
                        TxError::SigError(format!(
                            "WrapperTx signature verification failed: {}",
                            err
                        ))
                    })
            }
            // verify signature and extract signed data
            TxType::Protocol(protocol) => self
                .verify_signature(&protocol.pk, &self.unique_sechashes())
                .map(Option::Some)
                .map_err(|err| {
                    TxError::SigError(format!(
                        "ProtocolTx signature verification failed: {}",
                        err
                    ))
                }),
            // return as is
            TxType::Raw => Ok(None),
        }
    }

    /// Filter out all the sections that must not be submitted to the protocol
    /// and return them.
    pub fn protocol_filter(&mut self) -> Vec<Section> {
        let mut filtered = Vec::new();
        for i in (0..self.sections.len()).rev() {
            if let Section::MaspBuilder(_) = self.sections[i] {
                // MASP Builders containing extended full viewing keys amongst
                // other private information and must be removed prior to
                // submission to protocol
                filtered.push(self.sections.remove(i));
            }
        }
        filtered
    }

    /// Add an extra section to the tx builder by hash
    pub fn add_extra_section_from_hash(
        &mut self,
        hash: namada_core::hash::Hash,
        tag: Option<String>,
    ) -> namada_core::hash::Hash {
        self.add_section(Section::ExtraData(Code::from_hash(hash, tag)))
            .get_hash()
    }

    /// Add an extra section to the tx builder by code
    pub fn add_extra_section(
        &mut self,
        code: Vec<u8>,
        tag: Option<String>,
    ) -> (&mut Self, namada_core::hash::Hash) {
        let sechash = self
            .add_section(Section::ExtraData(Code::new(code, tag)))
            .get_hash();
        (self, sechash)
    }

    /// Add a memo section to the transaction
    pub fn add_memo(
        &mut self,
        memo: &[u8],
    ) -> (&mut Self, namada_core::hash::Hash) {
        let sechash = self
            .add_section(Section::ExtraData(Code::new(memo.to_vec(), None)))
            .get_hash();
        self.set_memo_sechash(sechash);
        (self, sechash)
    }

    /// Add a masp tx section to the tx builder
    pub fn add_masp_tx_section(
        &mut self,
        tx: Transaction,
    ) -> (&mut Self, MaspTxId) {
        let txid = tx.txid();
        self.add_section(Section::MaspTx(tx));
        (self, txid.into())
    }

    /// Add a masp builder section to the tx builder
    pub fn add_masp_builder(&mut self, builder: MaspBuilder) -> &mut Self {
        let _sec = self.add_section(Section::MaspBuilder(builder));
        self
    }

    /// Add wasm code to the tx builder from hash
    pub fn add_code_from_hash(
        &mut self,
        code_hash: namada_core::hash::Hash,
        tag: Option<String>,
    ) -> &mut Self {
        self.set_code(Code::from_hash(code_hash, tag));
        self
    }

    /// Add wasm code to the tx builder
    pub fn add_code(
        &mut self,
        code: Vec<u8>,
        tag: Option<String>,
    ) -> &mut Self {
        self.set_code(Code::new(code, tag));
        self
    }

    /// Add wasm data to the tx builder
    pub fn add_data(&mut self, data: impl BorshSerialize) -> &mut Self {
        let bytes = data.serialize_to_vec();
        self.set_data(Data::new(bytes));
        self
    }

    /// Add wasm data already serialized to the tx builder
    pub fn add_serialized_data(&mut self, bytes: Vec<u8>) -> &mut Self {
        self.set_data(Data::new(bytes));
        self
    }

    /// Add wrapper tx to the tx builder
    pub fn add_wrapper(
        &mut self,
        fee: Fee,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
    ) -> &mut Self {
        self.header.tx_type = TxType::Wrapper(Box::new(WrapperTx::new(
            fee, fee_payer, gas_limit,
        )));
        self
    }

    /// Add fee payer keypair to the tx builder
    pub fn sign_wrapper(&mut self, keypair: common::SecretKey) -> &mut Self {
        self.create_wrapper_sig(keypair, Authorization::new)
    }

    /// Mock adding fee payer keypair to the tx builder
    pub fn mock_sign_wrapper(
        &mut self,
        keypair: common::SecretKey,
    ) -> &mut Self {
        self.create_wrapper_sig(keypair, Authorization::mock)
    }

    fn create_wrapper_sig<F>(
        &mut self,
        keypair: common::SecretKey,
        create_sig: F,
    ) -> &mut Self
    where
        F: Fn(
            Vec<namada_core::hash::Hash>,
            BTreeMap<u8, common::SecretKey>,
            Option<Address>,
        ) -> Authorization,
    {
        self.protocol_filter();
        self.add_section(Section::Authorization(create_sig(
            self.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        self
    }

    /// Add signing keys to the tx builder
    pub fn sign_raw(
        &mut self,
        keypairs: Vec<common::SecretKey>,
        account_public_keys_map: AccountPublicKeysMap,
        signer: Option<Address>,
    ) -> &mut Self {
        self.create_sig_raw(
            keypairs,
            account_public_keys_map,
            signer,
            Authorization::new,
        )
    }

    /// Add signing keys to the tx builder with mock
    /// signatures
    pub fn mock(
        &mut self,
        keypairs: Vec<common::SecretKey>,
        account_public_keys_map: AccountPublicKeysMap,
        signer: Option<Address>,
    ) -> &mut Self {
        self.create_sig_raw(
            keypairs,
            account_public_keys_map,
            signer,
            Authorization::mock,
        )
    }

    fn create_sig_raw<F>(
        &mut self,
        keypairs: Vec<common::SecretKey>,
        account_public_keys_map: AccountPublicKeysMap,
        signer: Option<Address>,
        create_sig: F,
    ) -> &mut Self
    where
        F: Fn(
            Vec<namada_core::hash::Hash>,
            BTreeMap<u8, common::SecretKey>,
            Option<Address>,
        ) -> Authorization,
    {
        // The inner tx signer signs the Raw version of the Header
        let hashes = vec![self.raw_header_hash()];
        self.protocol_filter();

        let secret_keys = if signer.is_some() {
            account_public_keys_map.index_secret_keys(keypairs)
        } else {
            (0..).zip(keypairs).collect()
        };

        self.add_section(Section::Authorization(create_sig(
            hashes,
            secret_keys,
            signer,
        )));
        self
    }

    /// Add signatures
    pub fn add_signatures(
        &mut self,
        signatures: Vec<SignatureIndex>,
    ) -> &mut Self {
        self.protocol_filter();
        let mut pk_section = Authorization {
            targets: vec![self.raw_header_hash()],
            signatures: BTreeMap::new(),
            signer: Signer::PubKeys(vec![]),
        };
        // Put the supplied signatures into the correct sections
        for signature in signatures {
            if let Signer::PubKeys(pks) = &mut pk_section.signer {
                // Add the signature under its corresponding public key
                pk_section.signatures.insert(
                    u8::try_from(pks.len())
                        .expect("Number of PKs must not exceed u8 capacity"),
                    signature.signature,
                );
                pks.push(signature.pubkey);
            }
        }
        self.add_section(Section::Authorization(pk_section));
        self
    }

    /// Get the references to the inner transactions
    pub fn commitments(&self) -> &HashSet<TxCommitments> {
        &self.header.batch
    }

    /// Get the reference to the first inner transaction
    pub fn first_commitments(&self) -> Option<&TxCommitments> {
        self.header.batch.first()
    }

    /// Creates a batched tx from one or more inner transactions
    pub fn batch_tx(self, cmt: TxCommitments) -> BatchedTx {
        BatchedTx { tx: self, cmt }
    }

    /// Creates a batched tx along with the reference to the first inner tx
    pub fn batch_ref_first_tx(&self) -> Option<BatchedTxRef<'_>> {
        Some(BatchedTxRef {
            tx: self,
            cmt: self.first_commitments()?,
        })
    }

    /// Creates a batched tx along with a copy of the first inner tx
    #[cfg(any(test, feature = "testing"))]
    pub fn batch_first_tx(self) -> BatchedTx {
        let cmt = self.first_commitments().unwrap().to_owned();
        BatchedTx { tx: self, cmt }
    }
}

impl<'tx> Tx {
    /// Creates a batched tx along with the reference to one or more inner txs
    pub fn batch_ref_tx(
        &'tx self,
        cmt: &'tx TxCommitments,
    ) -> BatchedTxRef<'tx> {
        BatchedTxRef { tx: self, cmt }
    }
}

/// Represents the pointers to a indexed tx, which are the block height and the
/// index inside that block. Optionally points to a specific inner tx inside a
/// batch if such level of granularity is required.
#[derive(
    Debug,
    Copy,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct IndexedTx {
    /// The block height of the indexed tx
    pub block_height: BlockHeight,
    /// The index in the block of the tx
    pub block_index: TxIndex,
    /// The optional index of an inner tx within this batch
    pub batch_index: Option<u32>,
}

impl IndexedTx {
    /// Create an [`IndexedTx`] that upper bounds the entire range of
    /// txs in a block with some height `height`.
    pub const fn entire_block(height: BlockHeight) -> Self {
        Self {
            block_height: height,
            block_index: TxIndex(u32::MAX),
            batch_index: None,
        }
    }
}

impl Default for IndexedTx {
    fn default() -> Self {
        Self {
            block_height: BlockHeight::first(),
            block_index: TxIndex(0),
            batch_index: None,
        }
    }
}

impl Display for IndexedTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl FromStr for IndexedTx {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

/// Inclusive range of [`IndexedTx`] entries.
pub struct IndexedTxRange {
    lo: IndexedTx,
    hi: IndexedTx,
}

impl IndexedTxRange {
    /// Create a new [`IndexedTxRange`].
    pub const fn new(lo: IndexedTx, hi: IndexedTx) -> Self {
        Self { lo, hi }
    }

    /// Create a new [`IndexedTxRange`] over a range of [block
    /// heights](BlockHeight).
    pub const fn between_heights(from: BlockHeight, to: BlockHeight) -> Self {
        Self::new(
            IndexedTx {
                block_height: from,
                block_index: TxIndex(0),
                batch_index: None,
            },
            IndexedTx {
                block_height: to,
                block_index: TxIndex(u32::MAX),
                batch_index: Some(u32::MAX),
            },
        )
    }

    /// Create a new [`IndexedTxRange`] over a given [`BlockHeight`].
    pub const fn with_height(height: BlockHeight) -> Self {
        Self::between_heights(height, height)
    }

    /// The start of the range.
    pub const fn start(&self) -> IndexedTx {
        self.lo
    }

    /// The end of the range.
    pub const fn end(&self) -> IndexedTx {
        self.hi
    }
}

impl RangeBounds<IndexedTx> for IndexedTxRange {
    fn start_bound(&self) -> Bound<&IndexedTx> {
        Bound::Included(&self.lo)
    }

    fn end_bound(&self) -> Bound<&IndexedTx> {
        Bound::Included(&self.hi)
    }

    fn contains<U>(&self, item: &U) -> bool
    where
        IndexedTx: PartialOrd<U>,
        U: PartialOrd<IndexedTx> + ?Sized,
    {
        *item >= self.lo && *item <= self.hi
    }
}

/// A reference to a transaction with the commitment to a specific inner
/// transaction of the batch
#[derive(Debug, BorshSerialize)]
pub struct BatchedTxRef<'tx> {
    /// The transaction
    pub tx: &'tx Tx,
    /// The reference to the inner transaction
    pub cmt: &'tx TxCommitments,
}

/// A transaction with the commitment to a specific inner transaction of the
/// batch
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct BatchedTx {
    /// The transaction
    pub tx: Tx,
    /// The reference to the inner transaction
    pub cmt: TxCommitments,
}

impl BatchedTx {
    /// Convert owned version to a referenced one
    pub fn to_ref(&self) -> BatchedTxRef<'_> {
        BatchedTxRef {
            tx: &self.tx,
            cmt: &self.cmt,
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    use std::fs;

    use assert_matches::assert_matches;
    use data_encoding::HEXLOWER;
    use namada_core::address::testing::nam;
    use namada_core::borsh::schema::BorshSchema;
    use namada_core::key;
    use namada_core::token::DenominatedAmount;

    use super::*;
    use crate::data;
    use crate::data::protocol::{ProtocolTx, ProtocolTxType};

    /// Test that the BorshSchema for Tx gets generated without any name
    /// conflicts
    #[test]
    fn test_tx_schema() {
        let _declaration = Tx::declaration();
        let mut definitions = BTreeMap::new();
        Tx::add_definitions_recursively(&mut definitions);
    }

    /// Tx encoding must not change
    #[test]
    fn test_txs_fixture_decoding() {
        let file = fs::File::open("../tests/fixtures/txs.json")
            .expect("file should open read only");
        let serialized_txs: Vec<String> =
            serde_json::from_reader(file).expect("file should be proper JSON");

        for serialized_tx in serialized_txs {
            let raw_bytes = HEXLOWER.decode(serialized_tx.as_bytes()).unwrap();
            let tx = Tx::try_from_bytes(raw_bytes.as_ref()).unwrap();

            assert_eq!(tx.try_to_bytes().unwrap(), raw_bytes);
            assert_eq!(tx.to_bytes(), raw_bytes);
        }
    }

    #[test]
    fn test_tx_protobuf_serialization() {
        let tx = Tx::default();

        let buffer = tx.to_bytes();

        let deserialized = Tx::try_from_bytes(&buffer).unwrap();
        assert_eq!(tx, deserialized);
    }

    #[test]
    fn test_tx_json_serialization() {
        let tx = Tx::default();

        let mut buffer = vec![];
        tx.to_writer_json(&mut buffer).unwrap();

        let deserialized = Tx::try_from_json_bytes(&buffer).unwrap();
        assert_eq!(tx, deserialized);
    }

    #[test]
    fn test_wrapper_tx_signing() {
        let sk1 = key::testing::keypair_1();
        let sk2 = key::testing::keypair_2();
        let pk1 = sk1.to_public();
        let token = nam();

        let mut tx = Tx::default();
        tx.add_wrapper(
            data::wrapper::Fee {
                amount_per_gas_unit: DenominatedAmount::native(1.into()),
                token,
            },
            pk1,
            1.into(),
        );

        // Unsigned tx should fail validation
        tx.validate_tx().expect_err("Unsigned");

        {
            let mut tx = tx.clone();
            // Sign the tx
            tx.sign_wrapper(sk1);

            // Signed tx should pass validation
            tx.validate_tx()
                .expect("valid tx")
                .expect("with authorization");
        }

        {
            let mut tx = tx.clone();
            // Sign the tx with a wrong key
            tx.sign_wrapper(sk2);

            // Should be rejected
            tx.validate_tx().expect_err("invalid signature - wrong key");
        }
    }

    #[test]
    fn test_protocol_tx_signing() {
        let sk1 = key::testing::keypair_1();
        let sk2 = key::testing::keypair_2();
        let pk1 = sk1.to_public();
        let tx = Tx::from_type(TxType::Protocol(Box::new(ProtocolTx {
            pk: pk1,
            tx: ProtocolTxType::BridgePool,
        })));

        // Unsigned tx should fail validation
        tx.validate_tx().expect_err("Unsigned");

        {
            let mut tx = tx.clone();
            // Sign the tx
            tx.add_section(Section::Authorization(Authorization::new(
                tx.sechashes(),
                BTreeMap::from_iter([(0, sk1)]),
                None,
            )));

            // Signed tx should pass validation
            tx.validate_tx()
                .expect("valid tx")
                .expect("with authorization");
        }

        {
            let mut tx = tx.clone();
            // Sign the tx with a wrong key
            tx.add_section(Section::Authorization(Authorization::new(
                tx.sechashes(),
                BTreeMap::from_iter([(0, sk2)]),
                None,
            )));

            // Should be rejected
            tx.validate_tx().expect_err("invalid signature - wrong key");
        }
    }

    #[test]
    fn test_inner_tx_signing() {
        let sk1 = key::testing::keypair_1();
        let sk2 = key::testing::keypair_2();
        let pk1 = sk1.to_public();
        let pk2 = sk2.to_public();
        let pks_map = AccountPublicKeysMap::from_iter(vec![pk1.clone()]);
        let threshold = 1_u8;

        let tx = Tx::default();

        // Unsigned tx should fail validation
        tx.verify_signatures(
            &HashSet::from_iter([tx.header_hash()]),
            pks_map.clone(),
            &None,
            threshold,
            || Ok(()),
        )
        .expect_err("Unsigned");

        // Sign the tx
        {
            let mut tx = tx.clone();
            let signatures =
                tx.compute_section_signature(&[sk1], &pks_map, None);
            assert_eq!(signatures.len(), 1);
            tx.add_signatures(signatures);

            // Signed tx should pass validation
            let authorizations = tx
                .verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map.clone(),
                    &None,
                    threshold,
                    || Ok(()),
                )
                .expect("valid tx");
            assert_eq!(authorizations.len(), 1);
        }

        // Sign the tx with a wrong key
        {
            let mut tx = tx.clone();
            let pks_map_wrong =
                AccountPublicKeysMap::from_iter(vec![pk2.clone()]);
            let signatures =
                tx.compute_section_signature(&[sk2], &pks_map_wrong, None);
            assert_eq!(signatures.len(), 1);
            tx.add_signatures(signatures);

            // Should be rejected
            assert_matches!(
                tx.verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map.clone(),
                    &None,
                    threshold,
                    || Ok(()),
                ),
                Err(VerifySigError::InvalidSectionSignature(_))
            );
        }
    }

    #[test]
    fn test_inner_tx_multisig_signing() {
        let sk1 = key::testing::keypair_1();
        let sk2 = key::testing::keypair_2();
        let sk3 = key::testing::keypair_3();
        let pk1 = sk1.to_public();
        let pk2 = sk2.to_public();
        let pk3 = sk3.to_public();

        // A multisig with pk/sk 1 and 2 requiring both signatures
        let pks_map =
            AccountPublicKeysMap::from_iter(vec![pk1.clone(), pk2.clone()]);
        let threshold = 2_u8;
        let est_address =
            namada_core::address::testing::established_address_1();

        let tx = Tx::default();

        // Unsigned tx should fail validation
        tx.verify_signatures(
            &HashSet::from_iter([tx.header_hash()]),
            pks_map.clone(),
            &None,
            threshold,
            || Ok(()),
        )
        .expect_err("Unsigned");

        // Sign the tx with both keys
        {
            let mut tx = tx.clone();
            let signatures = tx.compute_section_signature(
                &[sk1.clone(), sk2.clone()],
                &pks_map,
                None,
            );
            assert_eq!(signatures.len(), 2);
            tx.add_signatures(signatures);

            // Signed tx should pass validation
            let authorizations = tx
                .verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map.clone(),
                    &None,
                    threshold,
                    || Ok(()),
                )
                .expect("valid tx");
            assert_eq!(authorizations.len(), 1);
        }

        // Sign the tx with one key only - sk1
        {
            let mut tx = tx.clone();
            let signatures =
                tx.compute_section_signature(&[sk1.clone()], &pks_map, None);
            assert_eq!(signatures.len(), 1);
            tx.add_signatures(signatures);

            // Should be rejected
            assert_matches!(
                tx.verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map.clone(),
                    &None,
                    threshold,
                    || Ok(()),
                ),
                Err(VerifySigError::InvalidSectionSignature(_))
            );
        }

        // Sign the tx with one key only - sk2
        {
            let mut tx = tx.clone();
            let pks_map_wrong = AccountPublicKeysMap::from_iter(vec![pk2]);
            let signatures =
                tx.compute_section_signature(&[sk2], &pks_map_wrong, None);
            assert_eq!(signatures.len(), 1);
            tx.add_signatures(signatures);

            // Should be rejected
            assert_matches!(
                tx.verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map.clone(),
                    &None,
                    threshold,
                    || Ok(()),
                ),
                Err(VerifySigError::InvalidSectionSignature(_))
            );
        }

        // Sign the tx with two keys but one of them incorrect - sk3
        {
            let mut tx = tx.clone();
            let pks_map_wrong =
                AccountPublicKeysMap::from_iter(vec![pk1.clone(), pk3]);
            let signatures = tx.compute_section_signature(
                &[sk1.clone(), sk3],
                &pks_map_wrong,
                None,
            );
            assert_eq!(signatures.len(), 2);
            tx.add_signatures(signatures);

            // Should be rejected
            assert_matches!(
                tx.verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map.clone(),
                    &None,
                    threshold,
                    || Ok(()),
                ),
                Err(VerifySigError::InvalidSectionSignature(_))
            );
        }

        // Sign the tx with one key but duplicate the signature to try
        // maliciously making it through the threshold check
        {
            let mut tx = tx.clone();
            let pks_map_wrong =
                AccountPublicKeysMap::from_iter(vec![pk1.clone()]);
            let signatures = tx.compute_section_signature(
                &[sk1.clone()],
                &pks_map_wrong,
                None,
            );
            assert_eq!(signatures.len(), 1);
            let sig = signatures.first().unwrap().to_owned();

            // Attach the duplicated signatures with the provided function
            let signatures = vec![sig.clone(), sig.clone()];
            tx.add_signatures(signatures);

            // Should be rejected
            assert_matches!(
                tx.verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map.clone(),
                    &None,
                    threshold,
                    || Ok(()),
                ),
                Err(VerifySigError::InvalidSectionSignature(_))
            );
        }

        // Sign the tx with one key but duplicate the signature to try
        // maliciously making it through the threshold check. This time avoid
        // using the provided constructor and attach the signatures manually
        {
            let mut tx = tx.clone();
            let pks_map_wrong =
                AccountPublicKeysMap::from_iter(vec![pk1.clone()]);
            let signatures = tx.compute_section_signature(
                &[sk1.clone()],
                &pks_map_wrong,
                None,
            );
            assert_eq!(signatures.len(), 1);
            let sig = signatures.first().unwrap().to_owned();

            let auth = Authorization {
                targets: vec![tx.header_hash()],
                signatures: [(0, sig.signature)].into(),
                signer: Signer::PubKeys(vec![pk1.clone()]),
            };
            tx.add_section(Section::Authorization(auth.clone()));
            tx.add_section(Section::Authorization(auth));

            // Should be rejected
            assert_matches!(
                tx.verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map.clone(),
                    &None,
                    threshold,
                    || Ok(()),
                ),
                Err(VerifySigError::InvalidSectionSignature(_))
            );
        }

        // Sign the tx with one key but duplicate the signature to try
        // maliciously making it through the threshold check. This time avoid
        // using the provided constructor and attach the signatures manually,
        // also disguise the duplicated signature to avoid the protocol check on
        // duplicated sections
        {
            let mut tx = tx.clone();
            let pks_map_wrong =
                AccountPublicKeysMap::from_iter(vec![pk1.clone()]);
            let signatures = tx.compute_section_signature(
                &[sk1.clone()],
                &pks_map_wrong,
                None,
            );
            assert_eq!(signatures.len(), 1);
            let sig = signatures.first().unwrap().to_owned();

            let auth = Authorization {
                targets: vec![tx.header_hash()],
                signatures: [(0, sig.signature)].into(),
                signer: Signer::PubKeys(vec![pk1.clone()]),
            };
            let mut auth2 = auth.clone();
            auth2.signer = Signer::Address(est_address.clone());
            tx.add_section(Section::Authorization(auth));
            tx.add_section(Section::Authorization(auth2));

            // Should be rejected
            assert_matches!(
                tx.verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map.clone(),
                    &None,
                    threshold,
                    || Ok(()),
                ),
                Err(VerifySigError::InvalidSectionSignature(_))
            );
        }

        // Sign the tx with one key but duplicate the signature to try
        // maliciously making it through the threshold check. This time avoid
        // using the provided constructor and attach the signatures manually,
        // also disguise the duplicated signature to avoid the protocol check on
        // duplicated sections and change the signature index
        {
            let mut tx = tx.clone();
            let pks_map_wrong =
                AccountPublicKeysMap::from_iter(vec![pk1.clone()]);
            let signatures =
                tx.compute_section_signature(&[sk1], &pks_map_wrong, None);
            assert_eq!(signatures.len(), 1);
            let sig = signatures.first().unwrap().to_owned();

            let auth = Authorization {
                targets: vec![tx.header_hash()],
                signatures: [(0, sig.signature.clone())].into(),
                signer: Signer::PubKeys(vec![pk1]),
            };
            let mut auth2 = auth.clone();
            auth2.signer = Signer::Address(est_address);
            auth2.signatures = [(1, sig.signature)].into();
            tx.add_section(Section::Authorization(auth));
            tx.add_section(Section::Authorization(auth2));

            // Should be rejected
            assert_matches!(
                tx.verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map.clone(),
                    &None,
                    threshold,
                    || Ok(()),
                ),
                Err(VerifySigError::InvalidSectionSignature(_))
            );
        }
    }

    #[test]
    fn test_inner_tx_sections() {
        let mut tx = Tx::default();
        assert!(tx.first_commitments().is_none());

        let cmt = TxCommitments::default();
        assert!(tx.code(&cmt).is_none());
        assert!(tx.data(&cmt).is_none());
        assert!(tx.memo(&cmt).is_none());

        // Set inner tx code
        let code_bytes = "code brrr".as_bytes();
        let code = Code::new(code_bytes.to_owned(), None);
        tx.set_code(code);
        assert!(tx.first_commitments().is_some());

        let cmt = tx.first_commitments().unwrap();
        assert!(tx.code(cmt).is_some());
        assert_eq!(tx.code(cmt).unwrap(), code_bytes);
        assert!(tx.data(cmt).is_none());
        assert!(tx.memo(cmt).is_none());

        let cmt = TxCommitments::default();
        assert!(tx.code(&cmt).is_none());
        assert!(tx.data(&cmt).is_none());
        assert!(tx.memo(&cmt).is_none());

        // Set inner tx data
        let data_bytes = "bingbong".as_bytes();
        let data = Data::new(data_bytes.to_owned());
        tx.set_data(data);
        assert!(tx.first_commitments().is_some());

        let cmt = tx.first_commitments().unwrap();
        assert!(tx.code(cmt).is_some());
        assert!(tx.data(cmt).is_some());
        assert_eq!(tx.data(cmt).unwrap(), data_bytes);
        assert!(tx.memo(cmt).is_none());

        let cmt = TxCommitments::default();
        assert!(tx.code(&cmt).is_none());
        assert!(tx.data(&cmt).is_none());
        assert!(tx.memo(&cmt).is_none());

        // Set inner tx memo
        let memo_bytes = "extradata".as_bytes();
        tx.add_memo(memo_bytes);
        assert!(tx.first_commitments().is_some());
        let cmt = tx.first_commitments().unwrap();
        assert!(tx.code(cmt).is_some());
        assert!(tx.data(cmt).is_some());
        assert!(tx.memo(cmt).is_some());
        assert_eq!(tx.memo(cmt).unwrap(), memo_bytes);

        let cmt = TxCommitments::default();
        assert!(tx.code(&cmt).is_none());
        assert!(tx.data(&cmt).is_none());
        assert!(tx.memo(&cmt).is_none());
    }

    #[test]
    fn test_batched_tx_sections() {
        let code_bytes1 = "code brrr".as_bytes();
        let data_bytes1 = "bingbong".as_bytes();
        let memo_bytes1 = "extradata".as_bytes();

        let code_bytes2 = code_bytes1;
        let data_bytes2 = "WASD".as_bytes();
        let memo_bytes2 = "hjkl".as_bytes();

        // Some duplicated sections
        let code_bytes3 = code_bytes1;
        let data_bytes3 = data_bytes2;
        let memo_bytes3 = memo_bytes1;

        let inner_tx1 = {
            let mut tx = Tx::default();

            let code = Code::new(code_bytes1.to_owned(), None);
            tx.set_code(code);

            let data = Data::new(data_bytes1.to_owned());
            tx.set_data(data);

            tx.add_memo(memo_bytes1);

            tx
        };

        let inner_tx2 = {
            let mut tx = Tx::default();

            let code = Code::new(code_bytes2.to_owned(), None);
            tx.set_code(code);

            let data = Data::new(data_bytes2.to_owned());
            tx.set_data(data);

            tx.add_memo(memo_bytes2);

            tx
        };

        let inner_tx3 = {
            let mut tx = Tx::default();

            let code = Code::new(code_bytes3.to_owned(), None);
            tx.set_code(code);

            let data = Data::new(data_bytes3.to_owned());
            tx.set_data(data);

            tx.add_memo(memo_bytes3);

            tx
        };

        let cmt1 = inner_tx1.first_commitments().unwrap().to_owned();
        let mut cmt2 = inner_tx2.first_commitments().unwrap().to_owned();
        let mut cmt3 = inner_tx3.first_commitments().unwrap().to_owned();

        // Batch `inner_tx1`, `inner_tx2` and `inner_tx3` into `tx`
        let tx = {
            let mut tx = Tx::default();

            tx.add_inner_tx(inner_tx1, cmt1.clone());
            assert_eq!(tx.first_commitments().unwrap(), &cmt1);
            assert_eq!(tx.header.batch.len(), 1);

            tx.add_inner_tx(inner_tx2, cmt2.clone());
            // Update cmt2 with the hash of cmt1 code section
            cmt2.code_hash = cmt1.code_hash;
            assert_eq!(tx.first_commitments().unwrap(), &cmt1);
            assert_eq!(tx.header.batch.len(), 2);
            assert_eq!(tx.header.batch.get_index(1).unwrap(), &cmt2);

            tx.add_inner_tx(inner_tx3, cmt3.clone());
            // Update cmt3 with the hash of cmt1 code and memo sections and the
            // hash of cmt2 data section
            cmt3.code_hash = cmt1.code_hash;
            cmt3.data_hash = cmt2.data_hash;
            cmt3.memo_hash = cmt1.memo_hash;
            assert_eq!(tx.first_commitments().unwrap(), &cmt1);
            assert_eq!(tx.header.batch.len(), 3);
            assert_eq!(tx.header.batch.get_index(2).unwrap(), &cmt3);

            tx
        };

        // Check sections of `inner_tx1`
        assert!(tx.code(&cmt1).is_some());
        assert_eq!(tx.code(&cmt1).unwrap(), code_bytes1);

        assert!(tx.data(&cmt1).is_some());
        assert_eq!(tx.data(&cmt1).unwrap(), data_bytes1);

        assert!(tx.memo(&cmt1).is_some());
        assert_eq!(tx.memo(&cmt1).unwrap(), memo_bytes1);

        // Check sections of `inner_tx2`
        assert!(tx.code(&cmt2).is_some());
        assert_eq!(tx.code(&cmt2).unwrap(), code_bytes2);

        assert!(tx.data(&cmt2).is_some());
        assert_eq!(tx.data(&cmt2).unwrap(), data_bytes2);

        assert!(tx.memo(&cmt2).is_some());
        assert_eq!(tx.memo(&cmt2).unwrap(), memo_bytes2);

        // Check sections of `inner_tx3`
        assert!(tx.code(&cmt3).is_some());
        assert_eq!(tx.code(&cmt3).unwrap(), code_bytes3);

        assert!(tx.data(&cmt3).is_some());
        assert_eq!(tx.data(&cmt3).unwrap(), data_bytes3);

        assert!(tx.memo(&cmt3).is_some());
        assert_eq!(tx.memo(&cmt3).unwrap(), memo_bytes3);

        // Check that the redundant sections have been included only once in the
        // batch
        assert_eq!(tx.sections.len(), 5);
        assert_eq!(
            tx.sections
                .iter()
                .filter(|section| section.code_sec().is_some())
                .count(),
            1
        );
        assert_eq!(
            tx.sections
                .iter()
                .filter(|section| section.data().is_some())
                .count(),
            2
        );
        assert_eq!(
            tx.sections
                .iter()
                .filter(|section| section.extra_data_sec().is_some())
                .count(),
            2
        );
    }
}
