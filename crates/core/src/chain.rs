//! Chain related data types

use std::fmt::{self, Display};
use std::num::ParseIntError;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::{HEXLOWER, HEXUPPER};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::hash::Hash;
use crate::time::DateTimeUtc;

/// The length of the block hash
pub const BLOCK_HASH_LENGTH: usize = 32;
/// The length of the block height
pub const BLOCK_HEIGHT_LENGTH: usize = 8;
/// The length of the chain ID string
pub const CHAIN_ID_LENGTH: usize = 30;
/// The maximum length of chain ID prefix
pub const CHAIN_ID_PREFIX_MAX_LEN: usize = 19;
/// Separator between chain ID prefix and the generated hash
pub const CHAIN_ID_PREFIX_SEP: char = '.';

/// Release default chain ID. Must be [`CHAIN_ID_LENGTH`] long.
pub const DEFAULT_CHAIN_ID: &str = "namada-internal.00000000000000";

/// Chain ID
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
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
)]
#[serde(transparent)]
pub struct ChainId(pub String);

impl ChainId {
    /// Extracts a string slice containing the entire chain ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derive the chain ID from the genesis hash and release version.
    pub fn from_genesis(
        ChainIdPrefix(prefix): ChainIdPrefix,
        genesis_bytes: impl AsRef<[u8]>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(genesis_bytes);
        // less `1` for chain ID prefix separator char
        // Cannot underflow as the `prefix.len` is checked
        #[allow(clippy::arithmetic_side_effects)]
        let width = CHAIN_ID_LENGTH - 1 - prefix.len();
        // lowercase hex of the first `width` chars of the hash
        let hash = format!("{:.width$x}", hasher.finalize(), width = width,);
        let raw = format!("{}{}{}", prefix, CHAIN_ID_PREFIX_SEP, hash);
        ChainId(raw)
    }

    /// Validate that chain ID is matching the expected value derived from the
    /// genesis hash and release version.
    pub fn validate(
        &self,
        genesis_bytes: impl AsRef<[u8]>,
    ) -> Vec<ChainIdValidationError> {
        let mut errors = vec![];
        match self.0.rsplit_once(CHAIN_ID_PREFIX_SEP) {
            Some((prefix, hash)) => {
                if prefix.len() > CHAIN_ID_PREFIX_MAX_LEN {
                    errors.push(ChainIdValidationError::Prefix(
                        ChainIdPrefixParseError::UnexpectedLen(prefix.len()),
                    ))
                }
                let mut hasher = Sha256::new();
                hasher.update(genesis_bytes);
                // less `1` for chain ID prefix separator char
                // Cannot underflow as the `prefix.len` is checked
                #[allow(clippy::arithmetic_side_effects)]
                let width = CHAIN_ID_LENGTH - 1 - prefix.len();
                // lowercase hex of the first `width` chars of the hash
                let expected_hash =
                    format!("{:.width$x}", hasher.finalize(), width = width,);
                if hash != expected_hash {
                    errors.push(ChainIdValidationError::InvalidHash(
                        expected_hash,
                        hash.to_string(),
                    ));
                }
            }
            None => {
                errors.push(ChainIdValidationError::MissingSeparator);
            }
        }
        errors
    }

    /// Find the prefix of a valid ChainId.
    pub fn prefix(&self) -> Option<ChainIdPrefix> {
        let ChainId(chain_id) = self;
        let (prefix, _) = chain_id.rsplit_once(CHAIN_ID_PREFIX_SEP)?;
        Some(ChainIdPrefix(prefix.to_string()))
    }
}

/// Height of a block, i.e. the level. The `default` is the
/// [`BlockHeight::sentinel`] value, which doesn't correspond to any block.
#[derive(
    Clone,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Serialize,
    Deserialize,
)]
pub struct BlockHeight(pub u64);

impl Default for BlockHeight {
    fn default() -> Self {
        Self::sentinel()
    }
}

impl Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<BlockHeight> for u64 {
    fn from(height: BlockHeight) -> Self {
        height.0
    }
}

impl FromStr for BlockHeight {
    type Err = ParseIntError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.parse::<u64>()?))
    }
}

/// Hash of a block as fixed-size byte array
#[derive(
    Clone,
    Default,
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
)]
pub struct BlockHash(pub [u8; BLOCK_HASH_LENGTH]);

impl Display for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXUPPER.encode(&self.0))
    }
}

impl From<Hash> for BlockHash {
    fn from(hash: Hash) -> Self {
        BlockHash(hash.0)
    }
}

impl From<u64> for BlockHeight {
    fn from(height: u64) -> Self {
        BlockHeight(height)
    }
}

impl From<tendermint::block::Height> for BlockHeight {
    fn from(height: tendermint::block::Height) -> Self {
        Self(u64::from(height))
    }
}

impl TryFrom<BlockHeight> for tendermint::block::Height {
    type Error = tendermint::Error;

    fn try_from(height: BlockHeight) -> std::result::Result<Self, Self::Error> {
        Self::try_from(height.0)
    }
}

impl TryFrom<i64> for BlockHeight {
    type Error = String;

    fn try_from(value: i64) -> std::result::Result<Self, Self::Error> {
        value
            .try_into()
            .map(BlockHeight)
            .map_err(|e| format!("Unexpected height value {}, {}", value, e))
    }
}

impl BlockHeight {
    /// The first block height 1.
    pub const fn first() -> Self {
        Self(1)
    }

    /// A sentinel value block height 0 may be used before any block is
    /// committed or in queries to read from the latest committed block.
    pub const fn sentinel() -> Self {
        Self(0)
    }

    /// Get the height of the next block
    pub fn next_height(&self) -> BlockHeight {
        BlockHeight(
            self.0
                .checked_add(1)
                .expect("Block height must not overflow"),
        )
    }

    /// Get the height of the previous block
    pub fn prev_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight(self.0.checked_sub(1)?))
    }

    /// Checked block height addition.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_add(self, rhs: impl Into<BlockHeight>) -> Option<Self> {
        let BlockHeight(rhs) = rhs.into();
        Some(Self(self.0.checked_add(rhs)?))
    }

    /// Checked block height subtraction.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_sub(self, rhs: impl Into<BlockHeight>) -> Option<Self> {
        let BlockHeight(rhs) = rhs.into();
        Some(Self(self.0.checked_sub(rhs)?))
    }
}

impl TryFrom<&[u8]> for BlockHash {
    type Error = ParseBlockHashError;

    fn try_from(value: &[u8]) -> Result<Self, ParseBlockHashError> {
        if value.len() != BLOCK_HASH_LENGTH {
            return Err(ParseBlockHashError::ParseBlockHash(format!(
                "Unexpected block hash length {}, expected {}",
                value.len(),
                BLOCK_HASH_LENGTH
            )));
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(value);
        Ok(BlockHash(hash))
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParseBlockHashError {
    #[error("Error parsing block hash: {0}")]
    ParseBlockHash(String),
}

impl core::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = HEXLOWER.encode(&self.0);
        f.debug_tuple("BlockHash").field(&hash).finish()
    }
}

/// Epoch identifier. Epochs are identified by consecutive numbers.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Copy,
    Default,
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
    Serialize,
    Deserialize,
)]
pub struct Epoch(pub u64);

impl Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Epoch {
    type Err = ParseIntError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let raw: u64 = u64::from_str(s)?;
        Ok(Self(raw))
    }
}

impl Epoch {
    /// Change to the next epoch
    pub fn next(&self) -> Self {
        Self(self.0.checked_add(1).expect("Epoch shouldn't overflow"))
    }

    /// Change to the previous epoch.
    pub fn prev(&self) -> Option<Self> {
        Some(Self(self.0.checked_sub(1)?))
    }

    /// Iterate a range of consecutive epochs starting from `self` of a given
    /// length. Work-around for `Step` implementation pending on stabilization of <https://github.com/rust-lang/rust/issues/42168>.
    pub fn iter_range(self, len: u64) -> impl Iterator<Item = Epoch> + Clone {
        let start_ix: u64 = self.into();
        let end_ix: u64 = start_ix.saturating_add(len);
        (start_ix..end_ix).map(Epoch::from)
    }

    /// Iterate a range of epochs, inclusive of the start and end.
    pub fn iter_bounds_inclusive(
        start: Self,
        end: Self,
    ) -> impl DoubleEndedIterator<Item = Epoch> + Clone {
        let start_ix = start.0;
        let end_ix = end.0;
        (start_ix..=end_ix).map(Epoch::from)
    }

    /// Checked epoch addition.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_add(self, rhs: impl Into<Epoch>) -> Option<Self> {
        let Epoch(rhs) = rhs.into();
        Some(Self(self.0.checked_add(rhs)?))
    }

    /// Unchecked epoch addition.
    ///
    /// # Panic
    ///
    /// Panics on overflow. Care must be taken to only use this with trusted
    /// values that are known to be in a limited range (e.g. system parameters
    /// but not e.g. transaction variables).
    pub fn unchecked_add(self, rhs: impl Into<Epoch>) -> Self {
        self.checked_add(rhs)
            .expect("Epoch addition shouldn't overflow")
    }

    /// Checked epoch subtraction. Computes self - rhs, returning None if
    /// overflow occurred.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_sub(self, rhs: impl Into<Epoch>) -> Option<Self> {
        let Epoch(rhs) = rhs.into();
        Some(Self(self.0.checked_sub(rhs)?))
    }

    /// Checked epoch division.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_div(self, rhs: impl Into<Epoch>) -> Option<Self> {
        let Epoch(rhs) = rhs.into();
        Some(Self(self.0.checked_div(rhs)?))
    }

    /// Checked epoch multiplication.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_mul(self, rhs: impl Into<Epoch>) -> Option<Self> {
        let Epoch(rhs) = rhs.into();
        Some(Self(self.0.checked_mul(rhs)?))
    }

    /// Checked epoch integral reminder.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_rem(self, rhs: impl Into<Epoch>) -> Option<Self> {
        let Epoch(rhs) = rhs.into();
        Some(Self(self.0.checked_rem(rhs)?))
    }

    /// Checked epoch subtraction. Computes self - rhs, returning default
    /// `Epoch(0)` if overflow occurred.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn saturating_sub(self, rhs: Epoch) -> Self {
        self.checked_sub(rhs).unwrap_or_default()
    }
}

impl From<u64> for Epoch {
    fn from(epoch: u64) -> Self {
        Epoch(epoch)
    }
}

impl From<Epoch> for u64 {
    fn from(epoch: Epoch) -> Self {
        epoch.0
    }
}

/// Predecessor block epochs
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct Epochs {
    /// The block heights of the first block of each known epoch.
    /// Invariant: the values must be sorted in ascending order.
    pub first_block_heights: Vec<BlockHeight>,
}

impl Epochs {
    /// Record start of a new epoch at the given block height
    pub fn new_epoch(&mut self, block_height: BlockHeight) {
        self.first_block_heights.push(block_height);
    }

    /// Look up the epoch of a given block height. If the given height is
    /// greater than the current height, the current epoch will be returned even
    /// though an epoch for a future block cannot be determined.
    pub fn get_epoch(&self, block_height: BlockHeight) -> Option<Epoch> {
        if let Some((_first_known_epoch_height, rest)) =
            self.first_block_heights.split_first()
        {
            let mut epoch = Epoch::default();
            for next_block_height in rest {
                if block_height < *next_block_height {
                    return Some(epoch);
                } else {
                    epoch = epoch.next();
                }
            }
            return Some(epoch);
        }
        None
    }

    /// Look up the starting block height of an epoch at or before a given
    /// height.
    pub fn get_epoch_start_height(
        &self,
        height: BlockHeight,
    ) -> Option<BlockHeight> {
        for start_height in self.first_block_heights.iter().rev() {
            if *start_height <= height {
                return Some(*start_height);
            }
        }
        None
    }

    /// Look up the starting block height of the given epoch
    pub fn get_start_height_of_epoch(
        &self,
        epoch: Epoch,
    ) -> Option<BlockHeight> {
        if epoch.0 > self.first_block_heights.len() as u64 {
            return None;
        }
        let idx = usize::try_from(epoch.0).ok()?;
        self.first_block_heights.get(idx).copied()
    }

    /// Return all starting block heights for each successive Epoch.
    ///
    /// __INVARIANT:__ The returned values are sorted in ascending order.
    pub fn first_block_heights(&self) -> &[BlockHeight] {
        &self.first_block_heights
    }
}

/// The block header data from Tendermint header relevant for Namada storage
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer, Default,
)]
pub struct BlockHeader {
    /// Merkle root hash of block
    pub hash: Hash,
    /// Timestamp associated to block
    pub time: DateTimeUtc,
    /// Hash of the addresses of the next validator set
    pub next_validators_hash: Hash,
}

impl BlockHeader {
    /// The number of bytes when this header is encoded
    pub const fn encoded_len() -> usize {
        // checked in `test_block_header_encoded_len`
        103
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ChainIdValidationError {
    #[error(
        "The prefix separator character '{CHAIN_ID_PREFIX_SEP}' is missing"
    )]
    MissingSeparator,
    #[error("The chain ID hash is not valid, expected {0}, got {1}")]
    InvalidHash(String, String),
    #[error("Invalid prefix {0}")]
    Prefix(ChainIdPrefixParseError),
}

impl Default for ChainId {
    fn default() -> Self {
        Self(DEFAULT_CHAIN_ID.to_string())
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ChainIdParseError {
    #[error("Chain ID must be {CHAIN_ID_LENGTH} long, got {0}")]
    UnexpectedLen(usize),
    #[error(
        "The chain ID contains forbidden characters: {0:?}. Only alphanumeric \
         characters and `-`, `_` and `.` are allowed."
    )]
    ForbiddenCharacters(Vec<char>),
}

impl FromStr for ChainId {
    type Err = ChainIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let len = s.len();
        if len != CHAIN_ID_LENGTH {
            return Err(ChainIdParseError::UnexpectedLen(len));
        }
        let mut forbidden_chars = s
            .chars()
            .filter(|char| {
                !matches!(*char as u8, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.')
            })
            .peekable();
        if forbidden_chars.peek().is_some() {
            return Err(ChainIdParseError::ForbiddenCharacters(
                forbidden_chars.collect(),
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

/// Chain ID prefix
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
#[serde(transparent)]
pub struct ChainIdPrefix(String);

impl fmt::Display for ChainIdPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ChainIdPrefix {
    /// Extracts a string slice containing the entire chain ID prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return a temporary chain ID made only from the prefix. This is not a
    /// valid chain ID and is only to be used temporarily in a network setup.
    pub fn temp_chain_id(&self) -> ChainId {
        ChainId(self.0.clone())
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ChainIdPrefixParseError {
    #[error(
        "Chain ID prefix must at least 1 and up to {CHAIN_ID_PREFIX_MAX_LEN} \
         characters long, got {0}"
    )]
    UnexpectedLen(usize),
    #[error(
        "The prefix contains forbidden characters: {0:?}. Only alphanumeric \
         characters and `-`, `_` and `.` are allowed."
    )]
    ForbiddenCharacters(Vec<char>),
}

impl FromStr for ChainIdPrefix {
    type Err = ChainIdPrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let len = s.len();
        if !(1..=CHAIN_ID_PREFIX_MAX_LEN).contains(&len) {
            return Err(ChainIdPrefixParseError::UnexpectedLen(len));
        }
        let mut forbidden_chars = s
            .chars()
            .filter(|char| {
                !matches!(*char as u8, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.')
            })
            .peekable();
        if forbidden_chars.peek().is_some() {
            return Err(ChainIdPrefixParseError::ForbiddenCharacters(
                forbidden_chars.collect(),
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

/// Helpers for testing with storage types.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::ops::{Add, AddAssign, Sub};

    use proptest::prelude::*;

    use super::*;
    use crate::time::DateTimeUtc;

    impl<T> Add<T> for BlockHeight
    where
        T: Into<BlockHeight>,
    {
        type Output = BlockHeight;

        fn add(self, rhs: T) -> Self::Output {
            self.checked_add(rhs.into()).unwrap()
        }
    }

    impl<T> AddAssign<T> for BlockHeight
    where
        T: Into<BlockHeight>,
    {
        fn add_assign(&mut self, rhs: T) {
            *self = self.checked_add(rhs.into()).unwrap()
        }
    }

    impl<T> Add<T> for Epoch
    where
        T: Into<Epoch>,
    {
        type Output = Epoch;

        fn add(self, rhs: T) -> Self::Output {
            self.checked_add(rhs.into()).unwrap()
        }
    }

    impl<T> Sub<T> for Epoch
    where
        T: Into<Epoch>,
    {
        type Output = Epoch;

        fn sub(self, rhs: T) -> Self::Output {
            self.checked_sub(rhs.into()).unwrap()
        }
    }

    prop_compose! {
        /// Generate an arbitrary epoch
        pub fn arb_epoch()(epoch: u64) -> Epoch {
            Epoch(epoch)
        }
    }

    /// A dummy header used for testing
    pub fn get_dummy_header() -> BlockHeader {
        use crate::time::DurationSecs;
        BlockHeader {
            hash: Hash([0; 32]),
            #[allow(
                clippy::disallowed_methods,
                clippy::arithmetic_side_effects
            )]
            time: DateTimeUtc::now() + DurationSecs(5),
            next_validators_hash: Hash([0; 32]),
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::borsh::BorshSerializeExt;

    proptest! {
        /// Test any chain ID that is generated via `from_genesis` function is valid.
        #[test]
        fn test_any_generated_chain_id_is_valid(
            prefix in proptest::string::string_regex(r#"[A-Za-z0-9\.\-_]{1,19}"#).unwrap(),
            genesis_bytes in any::<Vec<u8>>(),
        ) {
            let chain_id_prefix = ChainIdPrefix::from_str(&prefix).unwrap();
            let chain_id = ChainId::from_genesis(chain_id_prefix, &genesis_bytes);
            // There should be no validation errors
            let errors = chain_id.validate(&genesis_bytes);
            assert!(errors.is_empty(), "There should be no validation errors {:#?}", errors);
        }
    }

    #[test]
    fn test_predecessor_epochs_and_heights() {
        let mut epochs = Epochs {
            first_block_heights: vec![BlockHeight::first()],
        };
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(0)),
            Some(BlockHeight(1))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));

        // epoch 1
        epochs.new_epoch(BlockHeight(10));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(1)),
            Some(BlockHeight(10))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch_start_height(BlockHeight(0)), None);
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(1)),
            Some(BlockHeight(1))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(9)), Some(Epoch(0)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(9)),
            Some(BlockHeight(1))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(10)), Some(Epoch(1)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(10)),
            Some(BlockHeight(10))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(11)), Some(Epoch(1)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(11)),
            Some(BlockHeight(10))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(1)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(100)),
            Some(BlockHeight(10))
        );

        // epoch 2
        epochs.new_epoch(BlockHeight(20));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(2)),
            Some(BlockHeight(20))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(9)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(10)), Some(Epoch(1)));
        assert_eq!(epochs.get_epoch(BlockHeight(11)), Some(Epoch(1)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(11)),
            Some(BlockHeight(10))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(20)),
            Some(BlockHeight(20))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(100)),
            Some(BlockHeight(20))
        );

        // epoch 3
        epochs.new_epoch(BlockHeight(200));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(3)),
            Some(BlockHeight(200))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(9)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(10)), Some(Epoch(1)));
        assert_eq!(epochs.get_epoch(BlockHeight(11)), Some(Epoch(1)));
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(100)),
            Some(BlockHeight(20))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(200)),
            Some(BlockHeight(200))
        );

        // epoch 4
        epochs.new_epoch(BlockHeight(300));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(4)),
            Some(BlockHeight(300))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));

        // epoch 5
        epochs.new_epoch(BlockHeight(499));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(5)),
            Some(BlockHeight(499))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));
        assert_eq!(epochs.get_epoch(BlockHeight(499)), Some(Epoch(5)));

        // epoch 6
        epochs.new_epoch(BlockHeight(500));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(6)),
            Some(BlockHeight(500))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));
        assert_eq!(epochs.get_epoch(BlockHeight(499)), Some(Epoch(5)));
        assert_eq!(epochs.get_epoch(BlockHeight(500)), Some(Epoch(6)));

        // epoch 7
        epochs.new_epoch(BlockHeight(550));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(7)),
            Some(BlockHeight(550))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));
        assert_eq!(epochs.get_epoch(BlockHeight(499)), Some(Epoch(5)));
        assert_eq!(epochs.get_epoch(BlockHeight(500)), Some(Epoch(6)));
        assert_eq!(epochs.get_epoch(BlockHeight(550)), Some(Epoch(7)));

        // epoch 8
        epochs.new_epoch(BlockHeight(600));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(7)),
            Some(BlockHeight(550))
        );
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(8)),
            Some(BlockHeight(600))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(500)), Some(Epoch(6)));
        assert_eq!(epochs.get_epoch(BlockHeight(550)), Some(Epoch(7)));
        assert_eq!(epochs.get_epoch(BlockHeight(600)), Some(Epoch(8)));

        // try to fetch height values out of range
        // at this point, the min known epoch is 7
        for e in [9, 10, 11, 12] {
            assert!(
                epochs.get_start_height_of_epoch(Epoch(e)).is_none(),
                "Epoch: {e}"
            );
        }
    }

    #[test]
    fn test_block_header_encoded_len() {
        #[allow(clippy::disallowed_methods)]
        let header = BlockHeader {
            hash: Hash::zero(),
            time: DateTimeUtc::now(),
            next_validators_hash: Hash::zero(),
        };
        let len = header.serialize_to_vec().len();
        assert_eq!(len, BlockHeader::encoded_len())
    }
}
