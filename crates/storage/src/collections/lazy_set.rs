//! Lazy set.

use std::fmt::Debug;
use std::marker::PhantomData;

use namada_core::storage::{self, DbKeySeg, KeySeg};
use thiserror::Error;

use super::super::Result;
use super::{LazyCollection, ReadError};
use crate::{ResultExt, StorageRead, StorageWrite};

/// A lazy set.
///
/// This can be used as an alternative to [`HashSet`] and
/// [`BTreeSet`]. In the lazy set, the elements do not reside in memory but are
/// instead read and written to storage sub-keys of the storage `key` used to
/// construct the set.
///
/// In the [`LazySet`], the type of key `K` can be anything that implements
/// [`storage::KeySeg`], and this trait is used to turn the keys into key
/// segments.
///
/// [`HashSet`]: `namada_core::collections::HashSet`
/// [`BTreeSet`]: `std::collections::BTreeSet`
#[derive(Debug)]
pub struct LazySet<K> {
    key: storage::Key,
    phantom_k: PhantomData<K>,
}

/// Possible sub-keys of a [`LazySet`]
#[derive(Clone, Debug, PartialEq)]
pub enum SubKey<K> {
    /// Literal set key
    Data(K),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Invalid storage key {0}")]
    InvalidSubKey(storage::Key),
}

impl<K> LazyCollection for LazySet<K>
where
    K: storage::KeySeg + Debug,
{
    type SubKey = SubKey<K>;
    type Value = ();

    /// Create or use an existing map with the given storage `key`.
    fn open(key: storage::Key) -> Self {
        Self {
            key,
            phantom_k: PhantomData,
        }
    }

    fn is_valid_sub_key(
        &self,
        key: &storage::Key,
    ) -> crate::Result<Option<Self::SubKey>> {
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
            if let Ok(key) = storage::KeySeg::parse(raw_sub_key) {
                Ok(Some(SubKey::Data(key)))
            } else {
                Err(ValidationError::InvalidSubKey(key.clone()))
                    .into_storage_result()
            }
        };

        // Match the suffix against expected sub-keys
        match &suffix.segments[..] {
            [DbKeySeg::StringSeg(sub)] => validate_sub_key(sub.clone()),
            [DbKeySeg::AddressSeg(sub)] => validate_sub_key(sub.raw()),
            _ => Err(ValidationError::InvalidSubKey(key.clone()))
                .into_storage_result(),
        }
    }

    fn is_data_sub_key(&self, key: &storage::Key) -> bool {
        matches!(self.is_valid_sub_key(key), Ok(Some(_)))
    }
}

// `LazySet` methods
impl<K> LazySet<K>
where
    K: storage::KeySeg,
{
    /// Returns whether the set contains a value.
    pub fn contains<S>(&self, storage: &S, key: &K) -> Result<bool>
    where
        S: StorageRead,
    {
        storage.has_key(&self.get_key(key))
    }

    /// Get the storage sub-key of a given raw key
    pub fn get_key(&self, key: &K) -> storage::Key {
        let key_str = key.to_db_key();
        self.key.push(&key_str).unwrap()
    }

    /// Inserts a key into the set.
    ///
    /// If the set did not have this key present, `false` is returned.
    /// If the set did have this key present, `true` is returned. Unlike in
    /// `std::collection::HashSet`, the key is also updated; this matters
    /// for types that can be `==` without being identical.
    pub fn insert<S>(&self, storage: &mut S, key: K) -> Result<bool>
    where
        S: StorageWrite + StorageRead,
    {
        let present = self.contains(storage, &key)?;

        let key = self.get_key(&key);
        storage.write(&key, ())?;

        Ok(present)
    }

    /// Tries to inserts a key into the set.
    ///
    /// An error is returned if the key is already present.
    pub fn try_insert<S>(&self, storage: &mut S, key: K) -> Result<()>
    where
        S: StorageWrite + StorageRead,
    {
        let present = self.contains(storage, &key)?;
        if present {
            return Err(crate::Error::new_const("Occupied"));
        }

        let key = self.get_key(&key);
        storage.write(&key, ())
    }

    /// Removes a key from the set if it's present, returning `true` if the key
    /// was in the set.
    pub fn remove<S>(&self, storage: &mut S, key: &K) -> Result<bool>
    where
        S: StorageWrite + StorageRead,
    {
        let present = self.contains(storage, key)?;

        if present {
            let key = self.get_key(key);
            storage.delete(&key)?;
        }

        Ok(present)
    }

    /// Returns whether the set contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: StorageRead,
    {
        let mut iter = crate::iter_prefix_bytes(storage, self.key.clone())?;
        Ok(iter.next().is_none())
    }

    /// Reads the number of elements in the map.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded maps to avoid gas usage increasing with the length of the
    /// set.
    #[allow(clippy::len_without_is_empty)]
    pub fn len<S>(&self, storage: &S) -> Result<u64>
    where
        S: StorageRead,
    {
        let iter = crate::iter_prefix_bytes(storage, self.key.clone())?;
        iter.count().try_into().into_storage_result()
    }

    /// An iterator visiting all keys. The iterator element type is `Result<K>`,
    /// because the iterator's call to `next` may fail with e.g. out of gas.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded sets to avoid gas usage increasing with the length of the
    /// set.
    pub fn iter<'iter>(
        &self,
        storage: &'iter impl StorageRead,
    ) -> Result<impl Iterator<Item = Result<K>> + 'iter> {
        let iter = crate::iter_prefix(storage, self.key.clone())?;
        Ok(iter.map(|key_val_res| {
            let (key, ()) = key_val_res?;
            let last_key_seg = key
                .last()
                .ok_or(ReadError::UnexpectedlyEmptyStorageKey)
                .into_storage_result()?;
            let key = K::parse(last_key_seg.raw()).into_storage_result()?;
            Ok(key)
        }))
    }
}

#[cfg(test)]
mod test {
    use namada_core::address::{self, Address};

    use super::*;
    use crate::testing::TestStorage;

    #[test]
    fn test_lazy_set_basics() -> crate::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_set = LazySet::<u32>::open(key);

        // The map should be empty at first
        assert!(lazy_set.is_empty(&storage)?);
        assert!(lazy_set.len(&storage)? == 0);
        assert!(!lazy_set.contains(&storage, &0)?);
        assert!(!lazy_set.contains(&storage, &1)?);
        assert!(lazy_set.iter(&storage)?.next().is_none());
        assert!(!lazy_set.remove(&mut storage, &0)?);
        assert!(!lazy_set.remove(&mut storage, &1)?);

        // Insert a new value and check that it's added
        let key = 123;
        lazy_set.insert(&mut storage, key)?;

        let key2 = 456;
        lazy_set.insert(&mut storage, key2)?;

        let key3 = 256;
        lazy_set.try_insert(&mut storage, key3).unwrap();

        assert!(!lazy_set.contains(&storage, &0)?);
        assert!(lazy_set.contains(&storage, &key)?);
        assert!(!lazy_set.is_empty(&storage)?);
        assert!(lazy_set.len(&storage)? == 3);
        let mut set_it = lazy_set.iter(&storage)?;
        assert_eq!(set_it.next().unwrap()?, key);
        assert_eq!(set_it.next().unwrap()?, key3);
        assert_eq!(set_it.next().unwrap()?, key2);
        drop(set_it);

        assert!(!lazy_set.contains(&storage, &0)?);
        assert!(lazy_set.contains(&storage, &key)?);
        assert!(lazy_set.contains(&storage, &key2)?);
        assert!(lazy_set.try_insert(&mut storage, key3).is_err());

        // Remove the values and check the map contents
        let removed = lazy_set.remove(&mut storage, &key)?;
        assert!(removed);
        assert!(!lazy_set.is_empty(&storage)?);
        assert!(lazy_set.len(&storage)? == 2);
        assert!(!lazy_set.contains(&storage, &0)?);
        assert!(!lazy_set.contains(&storage, &1)?);
        assert!(!lazy_set.contains(&storage, &123)?);
        assert!(lazy_set.contains(&storage, &456)?);
        assert!(!lazy_set.contains(&storage, &key)?);
        assert!(lazy_set.contains(&storage, &key2)?);
        assert!(lazy_set.iter(&storage)?.next().is_some());
        assert!(!lazy_set.remove(&mut storage, &key)?);
        let removed = lazy_set.remove(&mut storage, &key2)?;
        assert!(removed);
        assert!(lazy_set.len(&storage)? == 1);
        let removed = lazy_set.remove(&mut storage, &key3)?;
        assert!(removed);
        assert!(lazy_set.is_empty(&storage)?);
        assert!(lazy_set.len(&storage)? == 0);

        assert!(lazy_set.try_insert(&mut storage, key).is_ok());
        assert!(lazy_set.try_insert(&mut storage, key).is_err());

        let storage_key = lazy_set.get_key(&key);
        assert_eq!(
            lazy_set.is_valid_sub_key(&storage_key).unwrap(),
            Some(SubKey::Data(key))
        );

        let storage_key2 = lazy_set.get_key(&key2);
        assert_eq!(
            lazy_set.is_valid_sub_key(&storage_key2).unwrap(),
            Some(SubKey::Data(key2))
        );

        Ok(())
    }

    #[test]
    fn test_lazy_set_with_addr_key() -> crate::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_set = LazySet::<Address>::open(key);

        // Insert a new value and check that it's added
        let key = address::testing::established_address_1();
        lazy_set.insert(&mut storage, key.clone())?;

        assert_eq!(lazy_set.len(&storage)?, 1);
        let mut map_it = lazy_set.iter(&storage)?;
        assert_eq!(map_it.next().unwrap()?, key);
        drop(map_it);

        let key2 = address::testing::established_address_2();
        lazy_set.insert(&mut storage, key2.clone())?;

        assert_eq!(lazy_set.len(&storage)?, 2);
        let mut iter = lazy_set.iter(&storage)?;
        assert!(key < key2, "sanity check - this influences the iter order");
        assert_eq!(iter.next().unwrap()?, key);
        assert_eq!(iter.next().unwrap()?, key2);
        assert!(iter.next().is_none());
        drop(iter);

        let storage_key = lazy_set.get_key(&key);
        assert_eq!(
            lazy_set.is_valid_sub_key(&storage_key).unwrap(),
            Some(SubKey::Data(key))
        );

        let storage_key2 = lazy_set.get_key(&key2);
        assert_eq!(
            lazy_set.is_valid_sub_key(&storage_key2).unwrap(),
            Some(SubKey::Data(key2))
        );

        Ok(())
    }
}
