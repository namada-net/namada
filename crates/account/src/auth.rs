//! Public keys associated with an account for n-signature authorization.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::collections::HashMap;
use namada_core::hints;
use namada_core::key::common;
use namada_core::key::common::SignOrMockKey;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
    Default,
    PartialEq,
)]
/// Holds the public key map data as a bimap for efficient querying
pub struct AccountPublicKeysMap {
    /// Hashmap from public key to index
    pub pk_to_idx: HashMap<common::PublicKey, u8>,
    /// Hashmap from index key to public key
    pub idx_to_pk: HashMap<u8, common::PublicKey>,
}

impl FromIterator<common::PublicKey> for AccountPublicKeysMap {
    /// Creates a value from an iterator.
    ///
    /// # Panics
    ///
    /// Panics when given more than 255 keys.
    fn from_iter<T: IntoIterator<Item = common::PublicKey>>(iter: T) -> Self {
        let mut pk_to_idx = HashMap::new();
        let mut idx_to_pk = HashMap::new();

        for (index, public_key) in iter.into_iter().enumerate() {
            if hints::unlikely(index > u8::MAX as usize) {
                panic!(
                    "Only up to 255 signers are allowed in a multisig account"
                );
            }
            #[allow(clippy::cast_possible_truncation)]
            let ix = u8::try_from(index).unwrap();

            pk_to_idx.insert(public_key.to_owned(), ix);
            idx_to_pk.insert(ix, public_key.to_owned());
        }

        Self {
            pk_to_idx,
            idx_to_pk,
        }
    }
}

impl AccountPublicKeysMap {
    /// Retrieve a public key from the index
    pub fn get_public_key_from_index(
        &self,
        index: u8,
    ) -> Option<common::PublicKey> {
        self.idx_to_pk.get(&index).cloned()
    }

    /// Retrieve the index of a public key
    pub fn get_index_from_public_key(
        &self,
        public_key: &common::PublicKey,
    ) -> Option<u8> {
        self.pk_to_idx.get(public_key).cloned()
    }

    // FIXME: can remove this?
    /// Index the given set of secret keys
    pub fn index_secret_keys(
        &self,
        secret_keys: Vec<common::SecretKey>,
    ) -> BTreeMap<u8, common::SecretKey> {
        secret_keys
            .into_iter()
            .filter_map(|secret_key: common::SecretKey| {
                self.get_index_from_public_key(&secret_key.to_public())
                    .map(|index| (index, secret_key))
            })
            .collect()
    }

    /// Index the given set of keys
    pub fn index_keys<KEY>(&self, keys: Vec<KEY>) -> BTreeMap<u8, KEY>
    where
        KEY: SignOrMockKey,
    {
        keys.into_iter()
            .filter_map(|key| {
                self.get_index_from_public_key(&key.pubkey())
                    .map(|index| (index, key))
            })
            .collect()
    }
}
