//! Lazy map.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::storage::{self, DbKeySeg, KeySeg};
use thiserror::Error;

use super::super::Result;
use super::{LazyCollection, ReadError};
use crate::{ResultExt, StorageRead, StorageWrite};

/// Subkey corresponding to the data elements of the LazyMap
pub const DATA_SUBKEY: &str = "data";

/// Lazy map.
///
/// This can be used as an alternative to [`HashMap`] and
/// [`BTreeMap`]. In the lazy map, the elements do not reside in memory but are
/// instead read and written to storage sub-keys of the storage `key` used to
/// construct the map.
///
/// In the [`LazyMap`], the type of key `K` can be anything that implements
/// [`storage::KeySeg`] and this trait is used to turn the keys into key
/// segments.
///
/// [`HashMap`]: `namada_core::collections::HashMap`
#[derive(Debug)]
pub struct LazyMap<K, V, SON = super::Simple> {
    key: storage::Key,
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,
    phantom_son: PhantomData<SON>,
}

/// A `LazyMap` with another `LazyCollection` inside it's value `V`
pub type NestedMap<K, V> = LazyMap<K, V, super::Nested>;

/// Possible sub-keys of a [`LazyMap`]
#[derive(Clone, Debug, PartialEq)]
pub enum SubKey<K> {
    /// Data sub-key, further sub-keyed by its literal map key
    Data(K),
}

/// Possible sub-keys of a nested [`LazyMap`]
#[derive(Clone, Debug, PartialEq)]
pub enum NestedSubKey<K, S> {
    /// Data sub-key
    Data {
        /// Literal map key
        key: K,
        /// Sub-key in the nested collection
        nested_sub_key: S,
    },
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Invalid storage key {0}")]
    InvalidSubKey(storage::Key),
    #[error("Invalid nested storage key {0}")]
    InvalidNestedSubKey(storage::Key),
}

/// Trait used to facilitate collection of lazy maps into eager maps
pub trait Collectable {
    /// The type of the value of the lazy map
    type Collected;

    /// Collect the lazy map into an eager map
    fn collect_map<S: StorageRead>(
        &self,
        storage: &S,
    ) -> crate::Result<Self::Collected>;
}

impl<K, V> Collectable for LazyMap<K, V, super::Nested>
where
    K: Hash + Eq + Clone + Debug + storage::KeySeg + Ord,
    V: Collectable + LazyCollection + Debug,
{
    type Collected = BTreeMap<K, V::Collected>;

    fn collect_map<S>(&self, storage: &S) -> crate::Result<Self::Collected>
    where
        S: StorageRead,
    {
        let mut map = BTreeMap::<K, V::Collected>::new();
        for res in self.iter(storage)? {
            let (
                NestedSubKey::Data {
                    key,
                    nested_sub_key: _,
                },
                _,
            ) = res?;
            let next_layer = self.at(&key).collect_map(storage)?;
            map.insert(key, next_layer);
        }
        Ok(map)
    }
}

impl<K, V> Collectable for LazyMap<K, V, super::Simple>
where
    K: Hash + Eq + Clone + Debug + storage::KeySeg + Ord,
    V: BorshSerialize + BorshDeserialize + Clone + Debug + 'static,
{
    type Collected = BTreeMap<K, V>;

    fn collect_map<S>(&self, storage: &S) -> crate::Result<Self::Collected>
    where
        S: StorageRead,
    {
        let mut map = BTreeMap::<K, V>::new();
        for res in self.iter(storage)? {
            let (key, value) = res?;
            map.insert(key, value);
        }
        Ok(map)
    }
}

impl<K, V> LazyCollection for LazyMap<K, V, super::Nested>
where
    K: storage::KeySeg + Clone + Hash + Eq + Debug,
    V: LazyCollection + Debug,
{
    type SubKey = NestedSubKey<K, <V as LazyCollection>::SubKey>;
    type Value = <V as LazyCollection>::Value;

    fn open(key: storage::Key) -> Self {
        Self {
            key,
            phantom_k: PhantomData,
            phantom_v: PhantomData,
            phantom_son: PhantomData,
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
            if let Ok(key_in_kv) = storage::KeySeg::parse(raw_sub_key) {
                let nested = self.at(&key_in_kv).is_valid_sub_key(key)?;
                match nested {
                    Some(nested_sub_key) => Ok(Some(NestedSubKey::Data {
                        key: key_in_kv,
                        nested_sub_key,
                    })),
                    None => {
                        Err(ValidationError::InvalidNestedSubKey(key.clone()))
                            .into_storage_result()
                    }
                }
            } else {
                Err(ValidationError::InvalidSubKey(key.clone()))
                    .into_storage_result()
            }
        };

        // Match the suffix against expected sub-keys
        match &suffix.segments[..2] {
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
        match sub_key {
            Ok(Some(NestedSubKey::Data {
                key: parsed_key,
                nested_sub_key: _,
            })) => {
                let sub = self.at(&parsed_key);
                // Check in the nested collection
                sub.is_data_sub_key(key)
            }
            _ => false,
        }
    }
}

impl<K, V> LazyCollection for LazyMap<K, V, super::Simple>
where
    K: storage::KeySeg + Debug,
    V: BorshDeserialize + BorshSerialize + 'static + Debug,
{
    type SubKey = SubKey<K>;
    type Value = V;

    /// Create or use an existing map with the given storage `key`.
    fn open(key: storage::Key) -> Self {
        Self {
            key,
            phantom_k: PhantomData,
            phantom_v: PhantomData,
            phantom_son: PhantomData,
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
            if let Ok(key_in_kv) = storage::KeySeg::parse(raw_sub_key) {
                Ok(Some(SubKey::Data(key_in_kv)))
            } else {
                Err(ValidationError::InvalidSubKey(key.clone()))
                    .into_storage_result()
            }
        };

        // Match the suffix against expected sub-keys
        match &suffix.segments[..] {
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
        matches!(self.is_valid_sub_key(key), Ok(Some(_)))
    }
}

// Generic `LazyMap` methods that require no bounds on values `V`
impl<K, V, SON> LazyMap<K, V, SON>
where
    K: storage::KeySeg,
{
    /// Get the prefix of set's elements storage
    fn get_data_prefix(&self) -> storage::Key {
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap()
    }

    /// Get the sub-key of a given element
    pub fn get_data_key(&self, key: &K) -> storage::Key {
        let key_str = key.to_db_key();
        self.get_data_prefix().push(&key_str).unwrap()
    }
}

// `LazyMap` methods with nested `LazyCollection`s `V`
impl<K, V> LazyMap<K, V, super::Nested>
where
    K: storage::KeySeg + Clone + Hash + Eq + Debug,
    V: LazyCollection + Debug,
{
    /// Get a nested collection at given key `key`. If there is no nested
    /// collection at the given key, a new empty one will be provided. The
    /// nested collection may be manipulated through its methods.
    pub fn at(&self, key: &K) -> V {
        V::open(self.get_data_key(key))
    }

    /// Returns whether the nested map contains a certain key with data inside.
    pub fn contains<S>(&self, storage: &S, key: &K) -> Result<bool>
    where
        S: StorageRead,
    {
        let prefix = self.get_data_key(key);
        let mut iter = crate::iter_prefix_bytes(storage, prefix)?;
        Ok(iter.next().is_some())
    }

    /// Remove all map entries at a given key prefix
    pub fn remove_all<S>(&self, storage: &mut S, key: &K) -> Result<bool>
    where
        S: StorageRead + StorageWrite,
    {
        let is_data = self.contains(storage, key)?;

        let data_prefix = self.get_data_key(key);
        storage.delete_prefix(&data_prefix)?;

        Ok(is_data)
    }

    /// An iterator visiting all key-value elements, where the values are from
    /// the inner-most collection. The iterator element type is `Result<_>`,
    /// because iterator's call to `next` may fail with e.g. out of gas or
    /// data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded maps to avoid gas usage increasing with the length of the
    /// map.
    pub fn iter<'iter>(
        &'iter self,
        storage: &'iter impl StorageRead,
    ) -> Result<
        impl Iterator<
            Item = Result<(
                <Self as LazyCollection>::SubKey,
                <Self as LazyCollection>::Value,
            )>,
        > + 'iter,
    > {
        let iter = crate::iter_prefix_with_filter(
            storage,
            self.get_data_prefix(),
            |key| self.is_data_sub_key(key),
        )?;
        Ok(iter.map(|key_val_res| {
            let (key, val) = key_val_res?;
            let sub_key = LazyCollection::is_valid_sub_key(self, &key)?
                .ok_or(ReadError::UnexpectedlyEmptyStorageKey)
                .into_storage_result()?;
            Ok((sub_key, val))
        }))
    }

    /// Returns whether the map contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: StorageRead,
    {
        let mut iter =
            crate::iter_prefix_bytes(storage, self.get_data_prefix())?;
        Ok(iter.next().is_none())
    }
}

// `LazyMap` methods with borsh encoded values `V`
impl<K, V> LazyMap<K, V, super::Simple>
where
    K: storage::KeySeg,
    V: BorshDeserialize + BorshSerialize + 'static,
{
    /// Inserts a key-value pair into the map.
    ///
    /// The full storage key identifies the key in the pair, while the value is
    /// held within the storage key.
    ///
    /// If the map did not have this key present, `None` is returned.
    /// If the map did have this key present, the value is updated, and the old
    /// value is returned. Unlike in `std::collection::HashMap`, the key is also
    /// updated; this matters for types that can be `==` without being
    /// identical.
    pub fn insert<S>(
        &self,
        storage: &mut S,
        key: K,
        val: V,
    ) -> Result<Option<V>>
    where
        S: StorageWrite + StorageRead,
    {
        let previous = self.get(storage, &key)?;

        let data_key = self.get_data_key(&key);
        Self::write_key_val(storage, &data_key, val)?;

        Ok(previous)
    }

    /// Removes a key from the map if it's present, returning the value at the
    /// key if the key was previously in the map.
    pub fn remove<S>(&self, storage: &mut S, key: &K) -> Result<Option<V>>
    where
        S: StorageWrite + StorageRead,
    {
        let value = self.get(storage, key)?;

        if value.is_some() {
            let data_key = self.get_data_key(key);
            storage.delete(&data_key)?;
        }

        Ok(value)
    }

    /// Returns the value corresponding to the key, if any.
    pub fn get<S>(&self, storage: &S, key: &K) -> Result<Option<V>>
    where
        S: StorageRead,
    {
        let data_key = self.get_data_key(key);
        Self::read_key_val(storage, &data_key)
    }

    /// Update a value at the given key with the given function. If no existing
    /// value exists, the closure's argument will be `None`.
    pub fn update<S, F>(&self, storage: &mut S, key: K, f: F) -> Result<()>
    where
        S: StorageWrite + StorageRead,
        F: FnOnce(Option<V>) -> V,
    {
        let data_key = self.get_data_key(&key);
        let current = Self::read_key_val(storage, &data_key)?;
        let new = f(current);
        Self::write_key_val(storage, &data_key, new)?;
        Ok(())
    }

    /// Try update a value at the given key with the given function that may
    /// fail. If no existing value exists, the closure's argument will be
    /// `None`.
    pub fn try_update<S, F>(&self, storage: &mut S, key: K, f: F) -> Result<()>
    where
        S: StorageWrite + StorageRead,
        F: FnOnce(Option<V>) -> Result<V>,
    {
        let data_key = self.get_data_key(&key);
        let current = Self::read_key_val(storage, &data_key)?;
        let new = f(current)?;
        Self::write_key_val(storage, &data_key, new)?;
        Ok(())
    }

    /// Returns whether the map contains a key with a value.
    pub fn contains<S>(&self, storage: &S, key: &K) -> Result<bool>
    where
        S: StorageRead,
    {
        storage.has_key(&self.get_data_key(key))
    }

    /// Returns whether the map contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: StorageRead,
    {
        let mut iter =
            crate::iter_prefix_bytes(storage, self.get_data_prefix())?;
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
        let iter = crate::iter_prefix_bytes(storage, self.get_data_prefix())?;
        iter.count().try_into().into_storage_result()
    }

    /// An iterator visiting all key-value elements. The iterator element type
    /// is `Result<(K, V)>`, because iterator's call to `next` may fail with
    /// e.g. out of gas or data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded maps to avoid gas usage increasing with the length of the
    /// map.
    pub fn iter<'iter>(
        &self,
        storage: &'iter impl StorageRead,
    ) -> Result<impl Iterator<Item = Result<(K, V)>> + 'iter> {
        let iter = crate::iter_prefix(storage, self.get_data_prefix())?;
        Ok(iter.map(|key_val_res| {
            let (key, val) = key_val_res?;
            let last_key_seg = key
                .last()
                .ok_or(ReadError::UnexpectedlyEmptyStorageKey)
                .into_storage_result()?;
            let key = K::parse(last_key_seg.raw()).into_storage_result()?;
            Ok((key, val))
        }))
    }

    // /// Collect the lazy map into an eager map
    // pub fn collect<M, S>(&self, storage: &S) -> Result<M>
    // where
    //     S: StorageRead,
    //     M: EagerMapFromIter<K, V>,
    //     K: Eq + Hash + Ord,
    // {
    //     let it = self
    //         .iter(storage)?
    //         .map(|res| res.expect("Failed to unwrap a lazy map element"));
    //     Ok(M::from_iter(it))
    // }

    /// Reads a value from storage
    fn read_key_val<S>(
        storage: &S,
        storage_key: &storage::Key,
    ) -> Result<Option<V>>
    where
        S: StorageRead,
    {
        let res = storage.read(storage_key)?;
        Ok(res)
    }

    /// Write a value into storage
    fn write_key_val(
        storage: &mut impl StorageWrite,
        storage_key: &storage::Key,
        val: V,
    ) -> Result<()> {
        storage.write(storage_key, val)
    }
}

#[cfg(test)]
mod test {
    use namada_core::address::{self, Address};

    use super::*;
    use crate::testing::TestStorage;

    #[test]
    fn test_lazy_map_basics() -> crate::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_map = LazyMap::<u32, String>::open(key);

        // The map should be empty at first
        assert!(lazy_map.is_empty(&storage)?);
        assert_eq!(lazy_map.len(&storage)?, 0);
        assert!(!lazy_map.contains(&storage, &0)?);
        assert!(!lazy_map.contains(&storage, &1)?);
        assert!(lazy_map.iter(&storage)?.next().is_none());
        assert!(lazy_map.get(&storage, &0)?.is_none());
        assert!(lazy_map.get(&storage, &1)?.is_none());
        assert!(lazy_map.remove(&mut storage, &0)?.is_none());
        assert!(lazy_map.remove(&mut storage, &1)?.is_none());

        // Insert a new value and check that it's added
        let (key, val) = (123, "Test".to_string());
        lazy_map.insert(&mut storage, key, val.clone())?;

        let (key2, val2) = (456, "Test2".to_string());
        lazy_map.insert(&mut storage, key2, val2.clone())?;

        assert!(!lazy_map.contains(&storage, &0)?);
        assert!(lazy_map.contains(&storage, &key)?);
        assert!(!lazy_map.is_empty(&storage)?);
        assert_eq!(lazy_map.len(&storage)?, 2);
        let mut map_it = lazy_map.iter(&storage)?;
        assert_eq!(map_it.next().unwrap()?, (key, val.clone()));
        assert_eq!(map_it.next().unwrap()?, (key2, val2.clone()));
        drop(map_it);

        assert!(lazy_map.get(&storage, &0)?.is_none());
        assert_eq!(lazy_map.get(&storage, &key)?.unwrap(), val);
        assert_eq!(lazy_map.get(&storage, &key2)?.unwrap(), val2);

        let eager_map: BTreeMap<_, _> = lazy_map.collect_map(&storage)?;
        assert_eq!(
            eager_map,
            vec![(123, "Test".to_string()), (456, "Test2".to_string())]
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        );

        // Remove the values and check the map contents
        let removed = lazy_map.remove(&mut storage, &key)?.unwrap();
        assert_eq!(removed, val);
        assert!(!lazy_map.is_empty(&storage)?);
        assert_eq!(lazy_map.len(&storage)?, 1);
        assert!(!lazy_map.contains(&storage, &0)?);
        assert!(!lazy_map.contains(&storage, &1)?);
        assert!(!lazy_map.contains(&storage, &123)?);
        assert!(lazy_map.contains(&storage, &456)?);
        assert!(lazy_map.get(&storage, &0)?.is_none());
        assert!(lazy_map.get(&storage, &key)?.is_none());
        assert!(lazy_map.get(&storage, &key2)?.is_some());
        assert!(lazy_map.iter(&storage)?.next().is_some());
        assert!(lazy_map.remove(&mut storage, &key)?.is_none());
        let removed = lazy_map.remove(&mut storage, &key2)?.unwrap();
        assert_eq!(removed, val2);
        assert!(lazy_map.is_empty(&storage)?);
        assert_eq!(lazy_map.len(&storage)?, 0);

        let storage_key = lazy_map.get_data_key(&key);
        assert_eq!(
            lazy_map.is_valid_sub_key(&storage_key).unwrap(),
            Some(SubKey::Data(key))
        );

        let storage_key2 = lazy_map.get_data_key(&key2);
        assert_eq!(
            lazy_map.is_valid_sub_key(&storage_key2).unwrap(),
            Some(SubKey::Data(key2))
        );

        // Try to update a key that doesn't yet exist.
        let updated_val = "updated";
        lazy_map.update(&mut storage, key, |current| {
            assert!(current.is_none());
            updated_val.to_string()
        })?;
        // Try to update a key that exists.
        let updated_val_2 = "updated again";
        lazy_map.update(&mut storage, key, |current| {
            assert_eq!(&current.unwrap_or_default(), updated_val);
            updated_val_2.to_string()
        })?;
        assert_eq!(&lazy_map.get(&storage, &key)?.unwrap(), updated_val_2);

        Ok(())
    }

    #[test]
    fn test_lazy_map_with_addr_key() -> crate::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_map = LazyMap::<Address, String>::open(key);

        // Insert a new value and check that it's added
        let (key, val) = (
            address::testing::established_address_1(),
            "Test".to_string(),
        );
        lazy_map.insert(&mut storage, key.clone(), val.clone())?;

        assert_eq!(lazy_map.len(&storage)?, 1);
        let mut map_it = lazy_map.iter(&storage)?;
        assert_eq!(map_it.next().unwrap()?, (key.clone(), val.clone()));
        drop(map_it);

        let (key2, val2) = (
            address::testing::established_address_2(),
            "Test2".to_string(),
        );
        lazy_map.insert(&mut storage, key2.clone(), val2.clone())?;

        assert_eq!(lazy_map.len(&storage)?, 2);
        let mut map_it = lazy_map.iter(&storage)?;
        assert!(key < key2, "sanity check - this influences the iter order");
        assert_eq!(map_it.next().unwrap()?, (key.clone(), val));
        assert_eq!(map_it.next().unwrap()?, (key2.clone(), val2));
        assert!(map_it.next().is_none());
        drop(map_it);

        let storage_key = lazy_map.get_data_key(&key);
        assert_eq!(
            lazy_map.is_valid_sub_key(&storage_key).unwrap(),
            Some(SubKey::Data(key))
        );

        let storage_key2 = lazy_map.get_data_key(&key2);
        assert_eq!(
            lazy_map.is_valid_sub_key(&storage_key2).unwrap(),
            Some(SubKey::Data(key2))
        );

        Ok(())
    }

    #[test]
    fn test_nested_lazy_map_with_addr_key() -> crate::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_map = NestedMap::<Address, LazyMap<u64, String>>::open(key);

        // Insert a new value and check that it's added
        let (key, sub_key, val) = (
            address::testing::established_address_1(),
            1_u64,
            "Test".to_string(),
        );
        lazy_map
            .at(&key)
            .insert(&mut storage, sub_key, val.clone())?;

        assert_eq!(lazy_map.at(&key).len(&storage)?, 1);
        let mut map_it = lazy_map.iter(&storage)?;
        let expected_key = NestedSubKey::Data {
            key: key.clone(),
            nested_sub_key: SubKey::Data(sub_key),
        };
        assert_eq!(
            map_it.next().unwrap()?,
            (expected_key.clone(), val.clone())
        );
        drop(map_it);

        let (key2, sub_key2, val2) = (
            address::testing::established_address_2(),
            2_u64,
            "Test2".to_string(),
        );
        lazy_map
            .at(&key2)
            .insert(&mut storage, sub_key2, val2.clone())?;

        assert_eq!(lazy_map.at(&key2).len(&storage)?, 1);
        let mut map_it = lazy_map.iter(&storage)?;
        assert!(key < key2, "sanity check - this influences the iter order");
        let expected_key2 = NestedSubKey::Data {
            key: key2,
            nested_sub_key: SubKey::Data(sub_key2),
        };
        assert_eq!(map_it.next().unwrap()?, (expected_key, val));
        assert_eq!(map_it.next().unwrap()?, (expected_key2, val2));
        assert!(map_it.next().is_none());
        drop(map_it);

        Ok(())
    }

    #[test]
    fn test_nested_map_basics() -> crate::Result<()> {
        let mut storage = TestStorage::default();
        let key = storage::Key::parse("testing").unwrap();

        // A nested map from u32 -> String -> u32
        let nested_map = NestedMap::<u32, LazyMap<String, u32>>::open(key);

        assert!(nested_map.is_empty(&storage)?);
        assert!(nested_map.iter(&storage)?.next().is_none());

        // Insert a value
        nested_map
            .at(&0)
            .insert(&mut storage, "string1".to_string(), 100)?;

        assert!(!nested_map.is_empty(&storage)?);
        assert!(nested_map.iter(&storage)?.next().is_some());
        assert_eq!(
            nested_map.at(&0).get(&storage, &"string1".to_string())?,
            Some(100)
        );
        assert_eq!(
            nested_map.at(&0).get(&storage, &"string2".to_string())?,
            None
        );
        assert!(nested_map.contains(&storage, &0)?);

        // Insert more values
        nested_map
            .at(&1)
            .insert(&mut storage, "string1".to_string(), 200)?;
        nested_map
            .at(&0)
            .insert(&mut storage, "string2".to_string(), 300)?;

        assert!(nested_map.contains(&storage, &0)?);
        assert!(nested_map.contains(&storage, &1)?);

        let mut it = nested_map.iter(&storage)?;
        let (
            NestedSubKey::Data {
                key,
                nested_sub_key: SubKey::Data(inner_key),
            },
            inner_val,
        ) = it.next().unwrap()?;
        assert_eq!(key, 0);
        assert_eq!(inner_key, "string1".to_string());
        assert_eq!(inner_val, 100);

        let (
            NestedSubKey::Data {
                key,
                nested_sub_key: SubKey::Data(inner_key),
            },
            inner_val,
        ) = it.next().unwrap()?;
        assert_eq!(key, 0);
        assert_eq!(inner_key, "string2".to_string());
        assert_eq!(inner_val, 300);

        let (
            NestedSubKey::Data {
                key,
                nested_sub_key: SubKey::Data(inner_key),
            },
            inner_val,
        ) = it.next().unwrap()?;
        assert_eq!(key, 1);
        assert_eq!(inner_key, "string1".to_string());
        assert_eq!(inner_val, 200);

        // Next element should be None
        assert!(it.next().is_none());
        drop(it);

        // Start removing elements
        let rem = nested_map
            .at(&0)
            .remove(&mut storage, &"string2".to_string())?;
        assert_eq!(rem, Some(300));
        assert_eq!(
            nested_map.at(&0).get(&storage, &"string2".to_string())?,
            None
        );
        assert_eq!(nested_map.at(&0).len(&storage)?, 1_u64);
        assert_eq!(nested_map.at(&1).len(&storage)?, 1_u64);
        assert_eq!(nested_map.iter(&storage)?.count(), 2);

        // Start removing elements
        let rem = nested_map
            .at(&0)
            .remove(&mut storage, &"string1".to_string())?;
        assert_eq!(rem, Some(100));
        assert_eq!(
            nested_map.at(&0).get(&storage, &"string1".to_string())?,
            None
        );
        assert_eq!(nested_map.at(&0).len(&storage)?, 0_u64);
        assert_eq!(nested_map.at(&1).len(&storage)?, 1_u64);
        assert_eq!(nested_map.iter(&storage)?.count(), 1);
        assert!(!nested_map.contains(&storage, &0)?);
        assert!(nested_map.contains(&storage, &1)?);

        // Start removing elements
        let rem = nested_map
            .at(&1)
            .remove(&mut storage, &"string1".to_string())?;
        assert_eq!(rem, Some(200));
        assert_eq!(
            nested_map.at(&1).get(&storage, &"string1".to_string())?,
            None
        );
        assert_eq!(nested_map.at(&0).len(&storage)?, 0_u64);
        assert_eq!(nested_map.at(&1).len(&storage)?, 0_u64);
        assert!(nested_map.is_empty(&storage)?);

        Ok(())
    }

    #[test]
    fn test_nested_map_key_prefix_removal() {
        let mut storage = TestStorage::default();
        let key = storage::Key::parse("testing").unwrap();

        // A nested map from u32 -> String -> u32
        let nested_map = NestedMap::<u32, LazyMap<String, u32>>::open(key);
        nested_map
            .at(&0)
            .insert(&mut storage, "dingus".to_string(), 5)
            .unwrap();
        nested_map
            .at(&0)
            .insert(&mut storage, "zingus".to_string(), 3)
            .unwrap();
        nested_map
            .at(&1)
            .insert(&mut storage, "dingus".to_string(), 4)
            .unwrap();

        assert_eq!(nested_map.iter(&storage).unwrap().count(), 3);

        nested_map.remove_all(&mut storage, &0).unwrap();
        assert!(!nested_map.contains(&storage, &0).unwrap());
        assert_eq!(nested_map.iter(&storage).unwrap().count(), 1);

        nested_map.remove_all(&mut storage, &1).unwrap();
        assert!(!nested_map.contains(&storage, &1).unwrap());
        assert!(nested_map.is_empty(&storage).unwrap());
    }

    #[test]
    fn test_lazy_map_collection() {
        let mut storage = TestStorage::default();
        let key_s = storage::Key::parse("testing_simple").unwrap();
        let key_n = storage::Key::parse("testing_nested").unwrap();

        let simple = LazyMap::<String, u32>::open(key_s);
        simple
            .insert(&mut storage, "bartle".to_string(), 5)
            .unwrap();
        simple.insert(&mut storage, "doo".to_string(), 4).unwrap();

        let nested_map = NestedMap::<u32, LazyMap<String, u32>>::open(key_n);
        nested_map
            .at(&0)
            .insert(&mut storage, "dingus".to_string(), 5)
            .unwrap();
        nested_map
            .at(&0)
            .insert(&mut storage, "zingus".to_string(), 3)
            .unwrap();
        nested_map
            .at(&1)
            .insert(&mut storage, "dingus".to_string(), 4)
            .unwrap();

        let exp_simple =
            vec![("bartle".to_string(), 5), ("doo".to_string(), 4)]
                .into_iter()
                .collect::<BTreeMap<_, _>>();
        let mut exp_nested: BTreeMap<u32, BTreeMap<String, u32>> =
            BTreeMap::new();
        exp_nested
            .entry(0)
            .or_default()
            .insert("dingus".to_string(), 5);
        exp_nested
            .entry(0)
            .or_default()
            .insert("zingus".to_string(), 3);
        exp_nested
            .entry(1)
            .or_default()
            .insert("dingus".to_string(), 4);

        let simple_eager = simple.collect_map(&storage).unwrap();
        let nested_eager = nested_map.collect_map(&storage).unwrap();

        assert_eq!(exp_simple, simple_eager);
        assert_eq!(exp_nested, nested_eager);
    }
}
