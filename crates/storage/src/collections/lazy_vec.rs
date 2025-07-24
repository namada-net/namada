//! Lazy dynamically-sized vector.

use std::fmt::Debug;
use std::marker::PhantomData;

use namada_core::arith::checked;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::storage::{self, DbKeySeg, KeySeg};
use thiserror::Error;

use super::super::Result;
use super::LazyCollection;
use crate::{ResultExt, StorageRead, StorageWrite};

/// Subkey pointing to the length of the LazyVec
pub const LEN_SUBKEY: &str = "len";
/// Subkey corresponding to the data elements of the LazyVec
pub const DATA_SUBKEY: &str = "data";

/// Using `u64` for vector's indices
pub type Index = u64;

/// Lazy dynamically-sized vector.
///
/// This can be used as an alternative to `std::collections::Vec`. In the lazy
/// vector, the elements do not reside in memory but are instead read and
/// written to storage sub-keys of the storage `key` used to construct the
/// vector.
#[derive(Clone, Debug)]
pub struct LazyVec<T> {
    key: storage::Key,
    phantom: PhantomData<T>,
}

/// Possible sub-keys of a [`LazyVec`]
#[derive(Debug, PartialEq)]
pub enum SubKey {
    /// Length sub-key
    Len,
    /// Data sub-key, further sub-keyed by its index
    Data(Index),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Incorrect difference in LazyVec's length")]
    InvalidLenDiff,
    #[error("An empty LazyVec must be deleted from storage")]
    EmptyVecShouldBeDeleted,
    #[error("Push at a wrong index. Got {got}, expected {expected}.")]
    UnexpectedPushIndex { got: Index, expected: Index },
    #[error("Pop at a wrong index. Got {got}, expected {expected}.")]
    UnexpectedPopIndex { got: Index, expected: Index },
    #[error(
        "Update (or a combination of pop and push) at a wrong index. Got \
         {got}, expected maximum {max}."
    )]
    UnexpectedUpdateIndex { got: Index, max: Index },
    #[error("An index has overflown its representation: {0}")]
    IndexOverflow(<usize as TryInto<Index>>::Error),
    #[error("Unexpected underflow in `{0} - {0}`")]
    UnexpectedUnderflow(Index, Index),
    #[error("Invalid storage key {0}")]
    InvalidSubKey(storage::Key),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum UpdateError {
    #[error(
        "Invalid index into a LazyVec. Got {index}, but the length is {len}"
    )]
    InvalidIndex { index: Index, len: u64 },
}

impl<T> LazyCollection for LazyVec<T>
where
    T: BorshSerialize + BorshDeserialize + 'static + Debug,
{
    type SubKey = SubKey;
    type Value = T;

    /// Create or use an existing vector with the given storage `key`.
    fn open(key: storage::Key) -> Self {
        Self {
            key,
            phantom: PhantomData,
        }
    }

    /// Check if the given storage key is a valid LazyVec sub-key and if so
    /// return which one
    fn is_valid_sub_key(
        &self,
        key: &storage::Key,
    ) -> crate::Result<Option<SubKey>> {
        let suffix = match key.split_prefix(&self.key) {
            None => {
                // not matching prefix, irrelevant
                return Ok(None);
            }
            Some(None) => {
                // no suffix, invalid
                return Err(ValidationError::InvalidSubKey(key.clone()))
                    .into_storage_result();
            }
            Some(Some(suffix)) => suffix,
        };

        // A helper to validate the 2nd key segment
        let validate_sub_key = |raw_sub_key| {
            if let Ok(index) = storage::KeySeg::parse(raw_sub_key) {
                Ok(Some(SubKey::Data(index)))
            } else {
                Err(ValidationError::InvalidSubKey(key.clone()))
                    .into_storage_result()
            }
        };

        // Match the suffix against expected sub-keys
        match &suffix.segments[..] {
            [DbKeySeg::StringSeg(sub)] if sub == LEN_SUBKEY => {
                Ok(Some(SubKey::Len))
            }
            [DbKeySeg::StringSeg(sub_a), DbKeySeg::StringSeg(sub_b)]
                if sub_a == DATA_SUBKEY =>
            {
                validate_sub_key(sub_b.clone())
            }
            [DbKeySeg::StringSeg(sub_a), DbKeySeg::AddressSeg(sub_b)]
                if sub_a == DATA_SUBKEY =>
            {
                validate_sub_key(sub_b.raw())
            }
            _ => Err(ValidationError::InvalidSubKey(key.clone()))
                .into_storage_result(),
        }
    }

    fn is_data_sub_key(&self, key: &storage::Key) -> bool {
        let sub_key = self.is_valid_sub_key(key);
        // The `SubKey::Len` is not data sub-key
        matches!(sub_key, Ok(Some(SubKey::Data(_))))
    }
}

// Generic `LazyVec` methods that require no bounds on values `T`
impl<T> LazyVec<T> {
    /// Reads the number of elements in the vector.
    #[allow(clippy::len_without_is_empty)]
    pub fn len<S>(&self, storage: &S) -> Result<u64>
    where
        S: StorageRead,
    {
        let len = storage.read(&self.get_len_key())?;
        Ok(len.unwrap_or_default())
    }

    /// Returns `true` if the vector contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: StorageRead,
    {
        Ok(self.len(storage)? == 0)
    }

    /// Get the prefix of set's elements storage
    fn get_data_prefix(&self) -> storage::Key {
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap()
    }

    /// Get the sub-key of vector's elements storage
    fn get_data_key(&self, index: Index) -> storage::Key {
        self.get_data_prefix().push(&index).unwrap()
    }

    /// Get the sub-key of vector's length storage
    fn get_len_key(&self) -> storage::Key {
        self.key.push(&LEN_SUBKEY.to_owned()).unwrap()
    }
}

// `LazyVec` methods with borsh encoded values `T`
impl<T> LazyVec<T>
where
    T: BorshSerialize + BorshDeserialize + 'static + Debug,
{
    /// Appends an element to the back of a collection.
    pub fn push<S>(&self, storage: &mut S, val: T) -> Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let len = self.len(storage)?;
        let data_key = self.get_data_key(len);
        storage.write(&data_key, val)?;
        storage.write(&self.get_len_key(), checked!(len + 1)?)
    }

    /// Removes the last element from a vector and returns it, or `Ok(None)` if
    /// it is empty.
    ///
    /// Note that an empty vector is completely removed from storage.
    pub fn pop<S>(&self, storage: &mut S) -> Result<Option<T>>
    where
        S: StorageWrite + StorageRead,
    {
        let len = self.len(storage)?;
        if len == 0 {
            Ok(None)
        } else {
            let index = checked!(len - 1)?;
            let data_key = self.get_data_key(index);
            if len == 1 {
                storage.delete(&self.get_len_key())?;
            } else {
                storage.write(&self.get_len_key(), index)?;
            }
            let popped_val = storage.read(&data_key)?;
            storage.delete(&data_key)?;
            Ok(popped_val)
        }
    }

    /// Update an element at the given index.
    ///
    /// The index must be smaller than the length of the vector, otherwise this
    /// will fail with `UpdateError::InvalidIndex`.
    pub fn update<S>(&self, storage: &mut S, index: Index, val: T) -> Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let len = self.len(storage)?;
        if index >= len {
            return Err(UpdateError::InvalidIndex { index, len })
                .into_storage_result();
        }
        let data_key = self.get_data_key(index);
        storage.write(&data_key, val)
    }

    /// Read an element at the index or `Ok(None)` if out of bounds.
    pub fn get<S>(&self, storage: &S, index: Index) -> Result<Option<T>>
    where
        S: StorageRead,
    {
        storage.read(&self.get_data_key(index))
    }

    /// Read the first element
    pub fn front<S>(&self, storage: &S) -> Result<Option<T>>
    where
        S: StorageRead,
    {
        self.get(storage, 0)
    }

    /// Read the last element
    pub fn back<S>(&self, storage: &S) -> Result<Option<T>>
    where
        S: StorageRead,
    {
        let len = self.len(storage)?;
        self.get(storage, checked!(len - 1)?)
    }

    /// An iterator visiting all elements. The iterator element type is
    /// `Result<T>`, because iterator's call to `next` may fail with e.g. out of
    /// gas or data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded sets to avoid gas usage increasing with the length of the
    /// set.
    pub fn iter<'iter>(
        &self,
        storage: &'iter impl StorageRead,
    ) -> Result<impl Iterator<Item = Result<T>> + 'iter> {
        let iter = crate::iter_prefix(storage, self.get_data_prefix())?;
        Ok(iter.map(|key_val_res| {
            let (_key, val) = key_val_res?;
            Ok(val)
        }))
    }
}

#[cfg(test)]
mod test {
    use namada_core::address::{self, Address};

    use super::*;
    use crate::collections::lazy_map::{self, NestedMap};
    use crate::testing::TestStorage;

    #[test]
    fn test_lazy_vec_basics() -> crate::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_vec = LazyVec::<u32>::open(key);

        // The vec should be empty at first
        assert!(lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 0);
        assert!(lazy_vec.iter(&storage)?.next().is_none());
        assert!(lazy_vec.pop(&mut storage)?.is_none());
        assert!(lazy_vec.get(&storage, 0)?.is_none());
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        // Push a new value and check that it's added
        lazy_vec.push(&mut storage, 15_u32)?;
        assert!(!lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 1);
        assert_eq!(lazy_vec.iter(&storage)?.next().unwrap()?, 15_u32);
        assert_eq!(lazy_vec.get(&storage, 0)?.unwrap(), 15_u32);
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        // Pop the last value and check that the vec is empty again
        let popped = lazy_vec.pop(&mut storage)?.unwrap();
        assert_eq!(popped, 15_u32);
        assert!(lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 0);
        assert!(lazy_vec.iter(&storage)?.next().is_none());
        assert!(lazy_vec.pop(&mut storage)?.is_none());
        assert!(lazy_vec.get(&storage, 0)?.is_none());
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        let storage_key = lazy_vec.get_data_key(0);
        assert_eq!(
            lazy_vec.is_valid_sub_key(&storage_key).unwrap(),
            Some(SubKey::Data(0))
        );

        let storage_key2 = lazy_vec.get_data_key(1);
        assert_eq!(
            lazy_vec.is_valid_sub_key(&storage_key2).unwrap(),
            Some(SubKey::Data(1))
        );

        Ok(())
    }

    #[test]
    fn test_lazy_vec_with_addr() -> crate::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_vec = LazyVec::<Address>::open(key);

        // Push a new value and check that it's added
        let val = address::testing::established_address_1();
        lazy_vec.push(&mut storage, val.clone())?;
        assert!(!lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 1);
        assert_eq!(lazy_vec.iter(&storage)?.next().unwrap()?, val);
        assert_eq!(lazy_vec.get(&storage, 0)?.unwrap(), val);
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        let val2 = address::testing::established_address_2();
        lazy_vec.push(&mut storage, val2.clone())?;

        assert_eq!(lazy_vec.len(&storage)?, 2);
        let mut iter = lazy_vec.iter(&storage)?;
        // The iterator order follows the indices
        assert_eq!(iter.next().unwrap()?, val);
        assert_eq!(iter.next().unwrap()?, val2);
        assert!(iter.next().is_none());
        drop(iter);

        let storage_key = lazy_vec.get_data_key(0);
        assert_eq!(
            lazy_vec.is_valid_sub_key(&storage_key).unwrap(),
            Some(SubKey::Data(0))
        );

        let storage_key2 = lazy_vec.get_data_key(1);
        assert_eq!(
            lazy_vec.is_valid_sub_key(&storage_key2).unwrap(),
            Some(SubKey::Data(1))
        );

        Ok(())
    }

    /// Test iterator on a `LazyVec` nested inside a `LazyMap`
    #[test]
    fn test_nested_lazy_vec_iter() -> crate::Result<()> {
        let mut storage = TestStorage::default();

        let prefix = storage::Key::parse("test").unwrap();
        let handle = NestedMap::<Address, LazyVec<u32>>::open(prefix);

        let key = address::testing::established_address_1();

        // Push first value and check iterator
        handle.at(&key).push(&mut storage, 15)?;
        let expected = (
            lazy_map::NestedSubKey::Data {
                key: key.clone(),                // LazyMap key
                nested_sub_key: SubKey::Data(0), // LazyVec index
            },
            15, // the value
        );

        let mut iter = handle.iter(&storage)?;
        assert_eq!(iter.next().unwrap()?, expected);
        assert!(iter.next().is_none());
        drop(iter);

        // Push second value and check iterator again
        handle.at(&key).push(&mut storage, 1)?;
        let expected2 = (
            lazy_map::NestedSubKey::Data {
                key: key.clone(),                // LazyMap key
                nested_sub_key: SubKey::Data(1), // LazyVec index
            },
            1, // the value
        );

        let mut iter = handle.iter(&storage)?;
        assert_eq!(iter.next().unwrap()?, expected);
        assert_eq!(iter.next().unwrap()?, expected2);
        assert!(iter.next().is_none());
        drop(iter);

        let key2 = address::testing::established_address_2();
        // Push third value on a different outer key and check iterator again
        handle.at(&key2).push(&mut storage, 9)?;
        let expected3 = (
            lazy_map::NestedSubKey::Data {
                key: key2.clone(),               // LazyMap key
                nested_sub_key: SubKey::Data(0), // LazyVec index
            },
            9, // the value
        );

        let mut iter = handle.iter(&storage)?;
        assert!(key < key2, "sanity check - this influences the iter order");
        assert_eq!(iter.next().unwrap()?, expected);
        assert_eq!(iter.next().unwrap()?, expected2);
        assert_eq!(iter.next().unwrap()?, expected3);
        assert!(iter.next().is_none());
        drop(iter);

        Ok(())
    }
}
