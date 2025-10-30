//! Data-Types that are used in transactions.

#![allow(deprecated)] // Triggered by deprecated `TxType::Protocol

pub mod eval_vp;
/// txs to manage pgf
pub mod pgf;
/// txs to manage pos
pub mod pos;
/// wrapper txs
pub mod wrapper;

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use bitflags::bitflags;
use either::Either;
use namada_core::address::Address;
use namada_core::borsh::{
    BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
};
use namada_core::collections::HashMap;
use namada_core::hash::Hash;
use namada_core::storage;
use namada_events::Event;
use namada_gas::WholeGas;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use wrapper::*;

use crate::TxCommitments;

/// The different result codes that the ledger may send back to a client
/// indicating the status of their submitted tx.
/// The codes must not change with versions, only need ones may be added.
#[derive(
    Default,
    Debug,
    Copy,
    Clone,
    FromPrimitive,
    ToPrimitive,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum ResultCode {
    // WARN: These codes shouldn't be changed between version!
    // =========================================================================
    /// Success
    #[default]
    Ok = 0,
    /// Error in WASM tx execution
    WasmRuntimeError = 1,
    /// Invalid tx
    InvalidTx = 2,
    /// Invalid signature
    InvalidSig = 3,
    /// The block is full
    AllocationError = 4,
    /// Replayed tx
    ReplayTx = 5,
    /// Invalid chain ID
    InvalidChainId = 6,
    /// Expired tx
    ExpiredTx = 7,
    /// Exceeded gas limit
    TxGasLimit = 8,
    /// Error in paying tx fee
    FeeError = 9,
    /// Invalid vote extension
    InvalidVoteExtension = 10,
    /// Tx is too large
    TooLarge = 11,
    /// Tx code is not allowlisted
    TxNotAllowlisted = 12,
    // =========================================================================
    // WARN: These codes shouldn't be changed between version!
    /// Protocol txs are deprecated
    DeprecatedProtocolTx = 13,
}

impl ResultCode {
    /// Checks if the given [`ResultCode`] value is a protocol level error,
    /// that can be recovered from at the finalize block stage.
    pub const fn is_recoverable(&self) -> bool {
        use ResultCode::*;
        // NOTE: pattern match on all `ResultCode` variants, in order
        // to catch potential bugs when adding new codes
        match self {
            Ok | WasmRuntimeError => true,
            InvalidTx | InvalidSig | AllocationError | ReplayTx
            | InvalidChainId | ExpiredTx | TxGasLimit | FeeError
            | InvalidVoteExtension | TooLarge | TxNotAllowlisted
            | DeprecatedProtocolTx => false,
        }
    }

    /// Convert to `u32`.
    pub fn to_u32(&self) -> u32 {
        ToPrimitive::to_u32(self).unwrap()
    }

    /// Convert to `usize`.
    pub fn to_usize(&self) -> usize {
        ToPrimitive::to_usize(self).unwrap()
    }

    /// Convert from `u32`.
    pub fn from_u32(raw: u32) -> Option<Self> {
        FromPrimitive::from_u32(raw)
    }
}

impl From<ResultCode> for String {
    fn from(code: ResultCode) -> String {
        code.to_string()
    }
}

impl From<ResultCode> for u32 {
    fn from(code: ResultCode) -> u32 {
        code.to_u32()
    }
}

impl Display for ResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_u32())
    }
}

impl FromStr for ResultCode {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = u32::from_str(s).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        Self::from_u32(raw).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unexpected error code",
            )
        })
    }
}

impl From<ResultCode> for namada_core::tendermint::abci::Code {
    fn from(value: ResultCode) -> Self {
        Self::from(value.to_u32())
    }
}

/// Get the hash of a transaction
pub fn hash_tx(tx_bytes: &[u8]) -> Hash {
    let digest = Sha256::digest(tx_bytes);
    Hash(*digest.as_ref())
}

/// Compute the hash of the some inner tx in a batch.
pub fn compute_inner_tx_hash(
    wrapper_hash: Option<&Hash>,
    commitments: Either<&Hash, &TxCommitments>,
) -> Hash {
    const ZERO_HASH: Hash = Hash([0; 32]);

    let mut state = Sha256::new();
    state.update(wrapper_hash.unwrap_or(&ZERO_HASH));
    state.update(
        commitments
            .map_either(|hash| *hash, |commitments| commitments.get_hash()),
    );

    Hash(state.finalize_reset().into())
}

/// Identifier of an inner transaction in a batch.
pub struct InnerTxId<'tx> {
    /// Hash of the wrapper transaction, if any.
    pub wrapper_hash: Option<Cow<'tx, Hash>>,
    /// Hash of the inner transaction's commitments.
    pub commitments_hash: Cow<'tx, Hash>,
}

impl InnerTxId<'_> {
    /// Compute the hash of the wrapper transaction.
    ///
    /// The zero hash is returned in case no wrapper is
    /// present.
    #[inline]
    pub fn wrapper_hash(&self) -> Hash {
        self.wrapper_hash
            .as_ref()
            .map_or_else(Hash::zero, |wrapper_hash| {
                wrapper_hash.clone().into_owned()
            })
    }

    /// Compute the hash of the inner transaction.
    #[inline]
    pub fn inner_hash(&self) -> Hash {
        compute_inner_tx_hash(
            self.wrapper_hash.as_ref().map(|hash| hash.as_ref()),
            Either::Left(&self.commitments_hash),
        )
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
/// The result of a dry run, included the actual transaction result and the gas
/// used
pub struct DryRunResult(pub TxResult<String>, pub WholeGas);

/// Transaction application result. More specifically the set of inner tx
/// results indexed by the inner tx hash
// The generic is only used to return typed errors in protocol for error
// management with regards to replay protection, whereas for logging we use
// strings
// TODO derive BorshSchema after <https://github.com/near/borsh-rs/issues/82>
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct TxResult<T>(HashMap<Hash, Result<BatchedTxResult, T>>);

impl<T> Default for TxResult<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T: Serialize> Serialize for TxResult<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;

        for (k, v) in &self.0 {
            map.serialize_entry(&k.to_string(), v)?;
        }
        map.end()
    }
}

struct TxResultVisitor<T> {
    _phantom: PhantomData<T>,
}

impl<T> TxResultVisitor<T> {
    fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<'de, T> serde::de::Visitor<'de> for TxResultVisitor<T>
where
    T: serde::Deserialize<'de>,
{
    type Value = TxResult<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a transaction's result")
    }

    fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::MapAccess<'de>,
    {
        let mut result = TxResult::<T>::default();

        while let Some((key, value)) = map.next_entry()? {
            result.0.insert(
                Hash::from_str(key).map_err(serde::de::Error::custom)?,
                value,
            );
        }

        Ok(result)
    }
}

impl<'de, T: Deserialize<'de>> serde::Deserialize<'de> for TxResult<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(TxResultVisitor::new())
    }
}

impl<T: Display> TxResult<T> {
    /// Convert the batched result to a string
    pub fn to_result_string(self) -> TxResult<String> {
        let mut batch_results: HashMap<Hash, Result<BatchedTxResult, String>> =
            HashMap::new();

        for (hash, res) in self.0 {
            let res = match res {
                Ok(value) => Ok(value),
                Err(e) => Err(e.to_string()),
            };
            batch_results.insert(hash, res);
        }

        TxResult(batch_results)
    }
}

impl<T> Deref for TxResult<T> {
    type Target = HashMap<Hash, Result<BatchedTxResult, T>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for TxResult<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> TxResult<T> {
    /// Return a new set of tx results.
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Insert an inner tx result into this [`TxResult`].
    #[inline]
    pub fn insert_inner_tx_result(
        &mut self,
        wrapper_hash: Option<&Hash>,
        commitments: Either<&Hash, &TxCommitments>,
        result: Result<BatchedTxResult, T>,
    ) {
        self.0
            .insert(compute_inner_tx_hash(wrapper_hash, commitments), result);
    }

    /// Retrieve an inner tx result, if it exists.
    #[inline]
    pub fn get_inner_tx_result(
        &self,
        wrapper_hash: Option<&Hash>,
        commitments: Either<&Hash, &TxCommitments>,
    ) -> Option<&Result<BatchedTxResult, T>> {
        self.0
            .get(&compute_inner_tx_hash(wrapper_hash, commitments))
    }

    /// Check if all the inner txs in the collection have been successfully
    /// applied.
    #[inline]
    pub fn are_results_successfull(&self) -> bool {
        self.iter().all(|(_, res)| matches!(res, Ok(batched_result) if batched_result.is_accepted())
        )
    }

    /// Check if the collection of inner tx results contains any ok results.
    #[inline]
    pub fn are_any_ok(&self) -> bool {
        self.iter().any(|(_, res)| res.is_ok())
    }

    /// Check if the collection of inner tx results contains any errors.
    #[inline]
    pub fn are_any_err(&self) -> bool {
        self.iter().any(|(_, res)| res.is_err())
    }
}

#[cfg(feature = "migrations")]
namada_macros::derive_borshdeserializer!(TxResult::<String>);

/// The result of a specific tx in a batch
#[derive(
    Clone,
    Debug,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct BatchedTxResult {
    /// Storage keys touched by the transaction
    pub changed_keys: BTreeSet<storage::Key>,
    /// The results of all the triggered validity predicates by the transaction
    pub vps_result: VpsResult,
    /// New established addresses created by the transaction
    pub initialized_accounts: Vec<Address>,
    /// Events emitted by the transaction
    #[serde(skip_serializing, skip_deserializing)]
    #[borsh(skip)]
    pub events: BTreeSet<Event>,
}

impl BatchedTxResult {
    /// Check if the tx has been accepted by all the VPs
    pub fn is_accepted(&self) -> bool {
        self.vps_result.rejected_vps.is_empty()
    }
}

bitflags! {
    /// Validity predicate status flags.
    #[derive(
        Default, Debug, Clone, Copy, PartialEq, Eq,
        PartialOrd, Ord, Hash, Serialize, Deserialize,
    )]
    pub struct VpStatusFlags: u64 {
        /// The transaction had an invalid signature.
        const INVALID_SIGNATURE = 0b0000_0001;
    }
}

impl BorshSerialize for VpStatusFlags {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.bits(), writer)
    }
}

impl BorshDeserialize for VpStatusFlags {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        let bits = <u64 as BorshDeserialize>::deserialize_reader(reader)?;
        VpStatusFlags::from_bits(bits).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unexpected VpStatusFlags flag in input",
            )
        })
    }
}

#[cfg(feature = "migrations")]
namada_macros::derive_borshdeserializer!(VpStatusFlags);

/// Result of checking a transaction with validity predicates
// TODO derive BorshSchema after <https://github.com/near/borsh-rs/issues/82>
#[derive(
    Clone,
    Debug,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct VpsResult {
    /// The addresses whose VPs accepted the transaction
    pub accepted_vps: BTreeSet<Address>,
    /// The addresses whose VPs rejected the transaction
    pub rejected_vps: BTreeSet<Address>,
    /// Errors occurred in any of the VPs, if any
    pub errors: Vec<(Address, String)>,
    /// Validity predicate status flags, containing info
    /// about conditions that caused their evaluation to
    /// fail.
    pub status_flags: VpStatusFlags,
}

impl<T: Serialize> fmt::Display for TxResult<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "Transaction is valid.")
        } else {
            write!(f, "{}", serde_json::to_string(self).unwrap())
        }
    }
}

impl<T: for<'de> Deserialize<'de>> FromStr for TxResult<T> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl fmt::Display for BatchedTxResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "Transaction is {}. {} VPs result: {}",
                if self.is_accepted() {
                    "valid"
                } else {
                    "invalid"
                },
                iterable_to_string("Changed keys", self.changed_keys.iter()),
                self.vps_result,
            )
        } else {
            write!(f, "{}", serde_json::to_string(self).unwrap())
        }
    }
}

impl FromStr for BatchedTxResult {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl fmt::Display for VpsResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            iterable_to_string("Accepted", self.accepted_vps.iter()),
            iterable_to_string("Rejected", self.rejected_vps.iter()),
            iterable_to_string(
                "Errors",
                self.errors
                    .iter()
                    .map(|(addr, err)| format!("{} in {}", err, addr))
            ),
        )
    }
}

/// Format all the values of the given iterator into a string
fn iterable_to_string<T: fmt::Display>(
    label: &str,
    iter: impl Iterator<Item = T>,
) -> String {
    let mut iter = iter.peekable();
    if iter.peek().is_none() {
        "".into()
    } else {
        format!(
            " {}: {};",
            label,
            iter.map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        )
    }
}

/// Struct that classifies that kind of Tx
/// based on the contents of its data.
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
pub enum TxType {
    /// An ordinary tx
    Raw,
    /// A Tx that contains a payload in the form of a raw tx
    Wrapper(Box<WrapperTx>),
    /// Txs issued by validators as part of internal protocols
    #[deprecated]
    Protocol(Vec<u8>),
}

impl TxType {
    /// Produce a SHA-256 hash of this header  
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
    }
}

/// Sentinel used in transactions to signal events that require special
/// replay protection handling back to the protocol.
#[derive(Debug, Default)]
pub enum TxSentinel {
    /// No action required
    #[default]
    None,
    /// Exceeded gas limit
    OutOfGas,
    /// Found invalid commtiment to one of the transaction's sections
    InvalidCommitment,
}

impl TxSentinel {
    /// Set the sentinel for an out of gas error
    pub fn set_out_of_gas(&mut self) {
        *self = Self::OutOfGas
    }

    /// Set the sentinel for an invalid section commitment error
    pub fn set_invalid_commitment(&mut self) {
        *self = Self::InvalidCommitment
    }
}

#[cfg(test)]
mod test_process_tx {
    use assert_matches::assert_matches;
    use namada_core::address::testing::{
        established_address_1, established_address_3, nam,
    };
    use namada_core::address::{MASP, POS};
    use namada_core::key::*;
    use namada_core::token::{Amount, DenominatedAmount};
    use namada_events::extend::{ComposeEvent, TxHash};
    use namada_events::{EventLevel, EventType};

    use super::*;
    use crate::{Authorization, Code, Data, Section, Tx, TxError};

    fn gen_keypair() -> common::SecretKey {
        use rand::prelude::ThreadRng;
        use rand::thread_rng;

        let mut rng: ThreadRng = thread_rng();
        ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap()
    }

    /// Test that process_tx correctly identifies a raw tx with no
    /// data and returns an identical copy
    #[test]
    fn test_process_tx_raw_tx_no_data() {
        let mut outer_tx = Tx::from_type(TxType::Raw);
        let code_sec = outer_tx
            .set_code(Code::new("wasm code".as_bytes().to_owned(), None))
            .clone();
        outer_tx.validate_tx().expect("Test failed");
        match outer_tx.header().tx_type {
            TxType::Raw => {
                assert_eq!(
                    code_sec.get_hash(),
                    outer_tx.first_commitments().unwrap().code_hash,
                )
            }
            _ => panic!("Test failed: Expected Raw Tx"),
        }
    }

    /// Test that process_tx correctly identifies tx containing
    /// a raw tx with some data and returns an identical copy
    /// of the inner data
    #[test]
    fn test_process_tx_raw_tx_some_data() {
        let mut tx = Tx::from_type(TxType::Raw);
        let code_sec = tx
            .set_code(Code::new("wasm code".as_bytes().to_owned(), None))
            .clone();
        let data_sec = tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()))
            .clone();

        tx.validate_tx().expect("Test failed");
        match tx.header().tx_type {
            TxType::Raw => {
                assert_eq!(code_sec.get_hash(), tx.header().batch[0].code_hash,);
                assert_eq!(data_sec.get_hash(), tx.header().batch[0].data_hash,);
            }
            _ => panic!("Test failed: Expected Raw Tx"),
        }
    }

    /// Test that process_tx correctly identifies a raw tx with some
    /// signed data and returns an identical copy of the inner data
    #[test]
    fn test_process_tx_raw_tx_some_signed_data() {
        let mut tx = Tx::from_type(TxType::Raw);
        let code_sec = tx
            .set_code(Code::new("wasm code".as_bytes().to_owned(), None))
            .clone();
        let data_sec = tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()))
            .clone();
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            [(0, gen_keypair())].into_iter().collect(),
            None,
        )));

        tx.validate_tx().expect("Test failed");
        match tx.header().tx_type {
            TxType::Raw => {
                assert_eq!(code_sec.get_hash(), tx.header().batch[0].code_hash,);
                assert_eq!(data_sec.get_hash(), tx.header().batch[0].data_hash,);
            }
            _ => panic!("Test failed: Expected Raw Tx"),
        }
    }

    /// Test that process_tx correctly identifies a wrapper tx with some
    /// data and extracts the signed data.
    #[test]
    fn test_process_tx_wrapper_tx() {
        let keypair = gen_keypair();
        // the signed tx
        let mut tx = Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(
                    Amount::from_uint(10, 0).expect("Test failed"),
                ),
                token: nam(),
            },
            keypair.ref_to(),
            0.into(),
        ))));
        tx.set_code(Code::new("wasm code".as_bytes().to_owned(), None));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        tx.add_section(Section::Authorization(Authorization::new(
            tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        tx.validate_tx().expect("Test failed");
    }

    /// Test that process_tx correctly returns an error on a wrapper tx
    /// with some unsigned data
    #[test]
    fn test_process_tx_wrapper_tx_unsigned() {
        let keypair = gen_keypair();
        // the signed tx
        let mut tx = Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(
                    Amount::from_uint(10, 0).expect("Test failed"),
                ),
                token: nam(),
            },
            keypair.ref_to(),
            0.into(),
        ))));
        tx.set_code(Code::new("wasm code".as_bytes().to_owned(), None));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        let result = tx.validate_tx().expect_err("Test failed");
        assert_matches!(result, TxError::SigError(_));
    }

    // Test that the serialization process for [`BatchedTxResult`] skips the
    // events field
    #[test]
    fn batched_tx_result_ser() {
        let event = Event::new(EventType::new("test-event"), EventLevel::Tx)
            .with(TxHash(Hash::zero()))
            .into();
        let event2 =
            Event::new(EventType::new("test-event-2"), EventLevel::Block)
                .with(TxHash(Hash::zero()))
                .into();

        let batched_result = BatchedTxResult {
            changed_keys: [
                namada_account::Key::wasm_code_name("test-name".to_string()),
                namada_account::Key::wasm_hash("test-name"),
            ]
            .into(),
            vps_result: VpsResult {
                accepted_vps: [MASP].into(),
                rejected_vps: [POS].into(),
                errors: vec![(POS, "Pos error".to_string())],
                status_flags: VpStatusFlags::empty(),
            },
            initialized_accounts: vec![
                established_address_1(),
                established_address_3(),
            ],
            events: BTreeSet::from([event, event2]),
        };

        let serialized = serde_json::to_vec(&batched_result).unwrap();
        let BatchedTxResult {
            changed_keys,
            vps_result,
            initialized_accounts,
            events,
        } = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(changed_keys, batched_result.changed_keys);
        assert_eq!(
            vps_result.accepted_vps,
            batched_result.vps_result.accepted_vps
        );
        assert_eq!(
            vps_result.rejected_vps,
            batched_result.vps_result.rejected_vps
        );
        assert_eq!(vps_result.errors, batched_result.vps_result.errors);
        assert_eq!(
            vps_result.status_flags,
            batched_result.vps_result.status_flags
        );
        assert_eq!(initialized_accounts, batched_result.initialized_accounts);
        assert!(events.is_empty());
    }
}
