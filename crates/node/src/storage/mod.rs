//! The storage module handles both the current state in-memory and the stored
//! state in DB.

mod rocksdb;

use std::fmt;

use arse_merkle_tree::H256;
use arse_merkle_tree::blake2b::Blake2bHasher;
use arse_merkle_tree::traits::Hasher;
use blake2b_rs::{Blake2b, Blake2bBuilder};
use namada_sdk::state::{FullAccessState, StorageHasher};
#[cfg(test)]
pub use rocksdb::SnapshotPath;
pub use rocksdb::{DbSnapshot, DbSnapshotMeta, RocksDBUpdateVisitor, open};

#[derive(Default)]
pub struct PersistentStorageHasher(Blake2bHasher);

pub type PersistentDB = rocksdb::RocksDB;

pub type PersistentState =
    FullAccessState<PersistentDB, PersistentStorageHasher>;

impl Hasher for PersistentStorageHasher {
    fn write_bytes(&mut self, h: &[u8]) {
        self.0.write_bytes(h)
    }

    fn finish(self) -> H256 {
        self.0.finish()
    }
}

impl StorageHasher for PersistentStorageHasher {
    fn hash(value: impl AsRef<[u8]>) -> H256 {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(value.as_ref());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl fmt::Debug for PersistentStorageHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PersistentStorageHasher")
    }
}

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"namada storage").build()
}

#[allow(clippy::arithmetic_side_effects, clippy::cast_sign_loss)]
#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use namada_sdk::borsh::BorshDeserialize;
    use namada_sdk::chain::{BlockHeight, ChainId};
    use namada_sdk::collections::HashMap;
    use namada_sdk::eth_bridge::storage::bridge_pool;
    use namada_sdk::eth_bridge::storage::proof::BridgePoolRootProof;
    use namada_sdk::ethereum_events::Uint;
    use namada_sdk::gas::STORAGE_ACCESS_GAS_PER_BYTE;
    use namada_sdk::hash::Hash;
    use namada_sdk::ibc::storage::{client_counter_key, ibc_key, is_ibc_key};
    use namada_sdk::keccak::KeccakHash;
    use namada_sdk::parameters::Parameters;
    use namada_sdk::state::merkle_tree::NO_DIFF_KEY_PREFIX;
    use namada_sdk::state::{
        self, DB, StateRead, StorageRead, StorageWrite, StoreType,
    };
    use namada_sdk::storage::{Key, KeySeg};
    use namada_sdk::token::conversion::update_allowed_conversions;
    use namada_sdk::{
        address, decode, encode, parameters, storage, token, validation,
    };
    use namada_vp::state::MerkleTree;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::test_runner::Config;
    use tempfile::TempDir;

    use super::*;
    use crate::shell::is_key_diff_storable;

    #[test]
    fn test_crud_value() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut state = PersistentState::open(
            db_path.path(),
            None,
            ChainId::default(),
            address::testing::nam(),
            None,
            is_key_diff_storable,
        );
        let key = Key::parse("key").expect("cannot parse the key string");
        let value: u64 = 1;
        let value_bytes = encode(&value);
        let value_bytes_len = value_bytes.len();

        // before insertion
        let (result, gas) = state.db_has_key(&key).expect("has_key failed");
        assert!(!result);
        assert_eq!(
            gas,
            (key.len() as u64 * STORAGE_ACCESS_GAS_PER_BYTE).into()
        );
        let (result, gas) = state.db_read(&key).expect("read failed");
        assert_eq!(result, None);
        assert_eq!(
            gas,
            (key.len() as u64 * STORAGE_ACCESS_GAS_PER_BYTE).into()
        );

        // insert
        state.db_write(&key, value_bytes).expect("write failed");

        // read
        let (result, gas) = state.db_has_key(&key).expect("has_key failed");
        assert!(result);
        assert_eq!(
            gas,
            (key.len() as u64 * STORAGE_ACCESS_GAS_PER_BYTE).into()
        );
        let (result, gas) = state.db_read(&key).expect("read failed");
        let read_value: u64 = decode(result.expect("value doesn't exist"))
            .expect("decoding failed");
        assert_eq!(read_value, value);
        assert_eq!(
            gas,
            ((key.len() as u64 + value_bytes_len as u64)
                * STORAGE_ACCESS_GAS_PER_BYTE)
                .into()
        );

        // delete
        state.db_delete(&key).expect("delete failed");

        // read again
        let (result, _) = state.db_has_key(&key).expect("has_key failed");
        assert!(!result);
        let (result, _) = state.db_read(&key).expect("read failed");
        assert_eq!(result, None);
    }

    #[test]
    fn test_commit_block() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut state = PersistentState::open(
            db_path.path(),
            None,
            ChainId::default(),
            address::testing::nam(),
            None,
            is_key_diff_storable,
        );
        state
            .in_mem_mut()
            .begin_block(BlockHeight(100))
            .expect("begin_block failed");
        state
            .in_mem_mut()
            .block
            .pred_epochs
            .new_epoch(BlockHeight(1));
        let key = Key::parse("key").expect("cannot parse the key string");
        let value: u64 = 1;
        let value_bytes = encode(&value);
        // initialize parameter storage
        let params = Parameters::default();
        parameters::init_storage(&params, &mut state).expect("Test failed");
        // insert and commit
        state.db_write(&key, &value_bytes).expect("write failed");
        state.in_mem_mut().block.epoch = state.in_mem().block.epoch.next();
        state
            .in_mem_mut()
            .block
            .pred_epochs
            .new_epoch(BlockHeight(100));

        // update conversion for a new epoch
        update_allowed_conversions::<_, parameters::Store<_>, token::Store<_>>(
            &mut state,
        )
        .expect("update conversions failed");
        state.commit_block().expect("commit failed");

        // save the last state and the storage
        let root = state.in_mem().merkle_root().0;
        let address_gen = state.in_mem().address_gen.clone();

        // Release DB lock
        drop(state);

        // Load the last state
        let state = PersistentState::open(
            db_path.path(),
            None,
            ChainId::default(),
            address::testing::nam(),
            None,
            is_key_diff_storable,
        );
        let (loaded_root, height) =
            state.in_mem().get_state().expect("no block exists");
        assert_eq!(loaded_root.0, root);
        assert_eq!(height, 100);
        assert_eq!(state.in_mem().address_gen, address_gen);
        let (val, _) = state.db_read(&key).expect("read failed");
        assert_eq!(val.expect("no value"), value_bytes);
    }

    #[test]
    fn test_iter() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut state = PersistentState::open(
            db_path.path(),
            None,
            ChainId::default(),
            address::testing::nam(),
            None,
            is_key_diff_storable,
        );

        let mut expected = Vec::new();
        let prefix = Key::parse("prefix").expect("cannot parse the key string");
        for i in (0..9).rev() {
            let key = prefix
                .push(&format!("{}", i))
                .expect("cannot push the key segment");
            let value_bytes = encode(&(i as u64));
            // insert
            state
                .db_write(&key, value_bytes.clone())
                .expect("write failed");
            expected.push((key.to_string(), value_bytes));
        }

        state.commit_block().expect("commit failed");

        let (iter, gas) = state.db_iter_prefix(&prefix).unwrap();
        assert_eq!(
            gas,
            ((prefix.len() as u64) * STORAGE_ACCESS_GAS_PER_BYTE).into()
        );
        for (k, v, gas) in iter {
            match expected.pop() {
                Some((expected_key, expected_val)) => {
                    assert_eq!(k, expected_key);
                    assert_eq!(v, expected_val);
                    let expected_gas = expected_key.len() + expected_val.len();
                    assert_eq!(gas, (expected_gas as u64).into());
                }
                None => panic!("read a pair though no expected pair"),
            }
        }
    }

    #[test]
    fn test_validity_predicate() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut state = PersistentState::open(
            db_path.path(),
            None,
            ChainId::default(),
            address::testing::nam(),
            None,
            is_key_diff_storable,
        );
        state
            .in_mem_mut()
            .begin_block(BlockHeight(100))
            .expect("begin_block failed");

        let addr = state
            .in_mem_mut()
            .address_gen
            .generate_address("test".as_bytes());
        let key = Key::validity_predicate(&addr);

        // not exist
        let (vp, gas) = state
            .validity_predicate::<validation::ParamKeys>(&addr)
            .expect("VP load failed");
        assert_eq!(vp, None);
        assert_eq!(
            gas,
            ((key.len() as u64) * STORAGE_ACCESS_GAS_PER_BYTE).into()
        );

        // insert
        let vp1 = Hash::sha256("vp1".as_bytes());
        state.db_write(&key, vp1).expect("write failed");

        // check
        let (vp_code_hash, gas) = state
            .validity_predicate::<validation::ParamKeys>(&addr)
            .expect("VP load failed");
        assert_eq!(vp_code_hash.expect("no VP"), vp1);
        assert_eq!(
            gas,
            (((key.len() + vp1.len()) as u64) * STORAGE_ACCESS_GAS_PER_BYTE)
                .into()
        );
    }

    proptest! {
        #![proptest_config(Config {
            cases: 5,
            .. Config::default()
        })]
        #[test]
        fn test_read_with_height(blocks_write_value in vec(any::<bool>(), 20)) {
            test_read_with_height_aux(blocks_write_value).unwrap()
        }

        #[test]
        fn test_get_merkle_tree(blocks_write_type in vec(0..5_u64, 50)) {
            test_get_merkle_tree_aux(blocks_write_type).unwrap()
        }
    }

    /// Test reads at arbitrary block heights.
    ///
    /// We generate `blocks_write_value` with random bools as the input to this
    /// function, then:
    ///
    /// 1. For each `blocks_write_value`, write the current block height if true
    ///    or delete otherwise.
    /// 2. We try to read from these heights to check that we get back expected
    ///    value if was written at that block height or `None` if it was
    ///    deleted.
    /// 3. We try to read past the last height and we expect the last written
    ///    value, if any.
    fn test_read_with_height_aux(
        blocks_write_value: Vec<bool>,
    ) -> namada_sdk::state::Result<()> {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut state = PersistentState::open(
            db_path.path(),
            None,
            ChainId::default(),
            address::testing::nam(),
            None,
            is_key_diff_storable,
        );

        // 1. For each `blocks_write_value`, write the current block height if
        // true or delete otherwise.
        // We `.enumerate()` height (starting from `0`)
        let mut blocks_write_value = blocks_write_value
            .into_iter()
            .enumerate()
            .map(|(height, write_value)| {
                println!(
                    "At height {height} will {}",
                    if write_value { "write" } else { "delete" }
                );
                // start from height 1 - 0 is sentinel
                (BlockHeight::from(height as u64 + 1), write_value)
            });

        let key = Key::parse("key").expect("cannot parse the key string");
        for (height, write_value) in blocks_write_value.clone() {
            state.in_mem_mut().begin_block(height)?;
            assert_eq!(
                height,
                state.in_mem().block.height,
                "sanity check - height is as expected"
            );

            if write_value {
                let value_bytes = encode(&state.in_mem().block.height);
                state.db_write(&key, value_bytes)?;
            } else {
                state.db_delete(&key)?;
            }

            state.commit_block()?;
        }

        // 2. We try to read from these heights to check that we get back
        // expected value if was written at that block height or
        // `None` if it was deleted.
        for (height, write_value) in blocks_write_value.clone() {
            let (value_bytes, _gas) =
                state.db_read_with_height(&key, height)?;
            if write_value {
                let value_bytes = value_bytes.unwrap_or_else(|| {
                    panic!("Couldn't read from height {height}")
                });
                let value: BlockHeight = decode(value_bytes).unwrap();
                assert_eq!(value, height);
            } else if value_bytes.is_some() {
                let value: BlockHeight = decode(value_bytes.unwrap()).unwrap();
                panic!("Expected no value at height {height}, got {}", value,);
            }
        }

        // 3. We try to read past the last height and we expect the last written
        // value, if any.

        // If height is >= storage.last_height, it should read the latest state.
        let is_last_write = blocks_write_value.next_back().unwrap().1;

        // The upper bound is arbitrary.
        for height in state.in_mem().get_last_block_height().0
            ..state.in_mem().get_last_block_height().0 + 10
        {
            let height = BlockHeight::from(height);
            let (value_bytes, _gas) =
                state.db_read_with_height(&key, height)?;
            if is_last_write {
                let value_bytes =
                    value_bytes.expect("Should have been written");
                let value: BlockHeight = decode(value_bytes).unwrap();
                assert_eq!(value, state.in_mem().get_last_block_height());
            } else if value_bytes.is_some() {
                let value: BlockHeight = decode(value_bytes.unwrap()).unwrap();
                panic!("Expected no value at height {height}, got {}", value,);
            }
        }

        Ok(())
    }

    /// Test the restore of the merkle tree
    fn test_get_merkle_tree_aux(
        blocks_write_type: Vec<u64>,
    ) -> namada_sdk::state::Result<()> {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut state = PersistentState::open(
            db_path.path(),
            None,
            ChainId::default(),
            address::testing::nam(),
            None,
            is_key_diff_storable,
        );
        // Prepare written keys for non-provable data, provable data (IBC), and
        // no diffed data
        let make_key = |suffix: u64| {
            // For three type keys
            match suffix % 3u64 {
                // for non-provable data
                0 => Key::parse(format!("key{suffix}")).unwrap(),
                // for provable data
                1 => ibc_key(format!("key{suffix}")).unwrap(),
                // for no diff
                _ => client_counter_key(),
            }
        };

        let num_keys = 5;
        let blocks_write_type = blocks_write_type.into_iter().enumerate().map(
            |(index, write_type)| {
                // try to update some keys at each height
                let height = BlockHeight::from(index as u64 / num_keys + 1);
                let key = make_key(index as u64 % num_keys);
                (height, key, write_type)
            },
        );

        let mut roots = HashMap::new();

        // write values at Height 0 like init_storage
        for i in 0..num_keys {
            let key = make_key(i);
            let value_bytes = encode(&state.in_mem().block.height);
            state.db_write(&key, value_bytes)?;
        }
        let key = bridge_pool::get_signed_root_key();
        let root_proof =
            BridgePoolRootProof::new((KeccakHash::default(), Uint::default()));
        let bytes = encode(&root_proof);
        state.db_write(&key, bytes)?;

        // Update and commit
        let height = BlockHeight(1);
        state.in_mem_mut().begin_block(height)?;
        // Epoch 0
        state.in_mem_mut().block.pred_epochs.new_epoch(height);
        let mut batch = PersistentState::batch();
        for (height, key, write_type) in blocks_write_type.clone() {
            if height != state.in_mem().block.height {
                if state.in_mem().block.height.0 % 5 == 0 {
                    // new epoch every 5 heights
                    state.in_mem_mut().block.epoch =
                        state.in_mem().block.epoch.next();
                    let height = state.in_mem().block.height;
                    state.in_mem_mut().block.pred_epochs.new_epoch(height);
                }
                state.commit_block_from_batch(batch)?;
                // to check the root later
                roots.insert(
                    state.in_mem().block.height,
                    state.in_mem().merkle_root(),
                );
                let next_height = state.in_mem().block.height.next_height();
                state.in_mem_mut().begin_block(next_height)?;
                batch = PersistentState::batch();
            }
            let persist_diffs = (state.diff_key_filter)(&key);
            let tree_key = if !persist_diffs {
                let prefix =
                    Key::from(NO_DIFF_KEY_PREFIX.to_string().to_db_key());
                prefix.join(&key)
            } else {
                key.clone()
            };
            match write_type {
                0 => {
                    // no update
                }
                1 => {
                    state.in_mem_mut().block.tree.delete(&tree_key)?;
                    state.db_delete(&key)?;
                }
                2 => {
                    let value_bytes = encode(&state.in_mem().block.height);
                    state
                        .in_mem_mut()
                        .block
                        .tree
                        .update(&tree_key, &value_bytes)?;
                    state.db_write(&key, value_bytes)?;
                }
                3 => {
                    state.in_mem_mut().block.tree.delete(&tree_key)?;
                    state.batch_delete_subspace_val(&mut batch, &key)?;
                }
                _ => {
                    let value_bytes = encode(&state.in_mem().block.height);
                    state
                        .in_mem_mut()
                        .block
                        .tree
                        .update(&tree_key, &value_bytes)?;
                    state.batch_write_subspace_val(
                        &mut batch,
                        &key,
                        value_bytes,
                    )?;
                }
            }
        }
        // save the last root
        let last_height = state.in_mem().block.height;
        roots.insert(last_height, state.in_mem().merkle_root());
        state.commit_block_from_batch(batch)?;

        let mut current_state = HashMap::new();
        for i in 0..num_keys {
            let key = make_key(i);
            current_state.insert(key, true);
        }
        // Check IBC subtree
        for (height, key, write_type) in blocks_write_type.clone() {
            if !is_ibc_key(&key) || key == client_counter_key() {
                continue;
            }
            let tree = state.get_merkle_tree(height, Some(StoreType::Ibc))?;
            // Check if the rebuilt tree's root is the same as the saved one
            assert_eq!(tree.root().0, roots.get(&height).unwrap().0);
            match write_type {
                0 => {
                    // data was not updated
                    if *current_state.get(&key).unwrap() {
                        assert!(tree.has_key(&key)?);
                    } else {
                        assert!(!tree.has_key(&key)?);
                    }
                }
                1 | 3 => {
                    // data was deleted
                    assert!(!tree.has_key(&key)?);
                    current_state.insert(key, false);
                }
                _ => {
                    // data was updated
                    assert!(tree.has_key(&key)?);
                    current_state.insert(key, true);
                }
            }
        }

        // Check NoDiff subtree
        let mut current_state = HashMap::new();
        for i in 0..num_keys {
            let key = make_key(i);
            current_state.insert(key, true);
        }
        // NoDiff subtree can be restored for the last 2 blocks
        let prev_last_height = last_height.prev_height().unwrap();
        for (height, key, write_type) in blocks_write_type {
            if key != client_counter_key() {
                continue;
            }
            let merkle_key =
                Key::from(NO_DIFF_KEY_PREFIX.to_string().to_db_key())
                    .join(&key);
            let tree = match state
                .get_merkle_tree(height, Some(StoreType::NoDiff))
            {
                Ok(tree) if height >= prev_last_height => {
                    // Check if the rebuilt tree's root is the same as the saved
                    // one
                    assert_eq!(tree.root().0, roots.get(&height).unwrap().0);
                    tree
                }
                Ok(_) => panic!("The tree at the height should be pruned"),
                // expected error because of no merkle subtree store
                // set an empty merkle tree as a dummy
                Err(_) => MerkleTree::<PersistentStorageHasher>::default(),
            };
            // Check the NoDiff subtree at the last height
            match write_type {
                0 => {
                    // data was not updated
                    if height >= prev_last_height {
                        if *current_state.get(&key).unwrap() {
                            assert!(tree.has_key(&merkle_key)?);
                        } else {
                            assert!(!tree.has_key(&merkle_key)?);
                        }
                    }
                }
                1 | 3 => {
                    // data was deleted
                    if height >= prev_last_height {
                        assert!(!tree.has_key(&merkle_key)?);
                    }
                    current_state.insert(key, false);
                }
                _ => {
                    // data was updated
                    if height >= prev_last_height {
                        assert!(tree.has_key(&merkle_key)?);
                    }
                    current_state.insert(key, true);
                }
            }
        }

        Ok(())
    }

    /// Test the restore of the merkle tree
    #[test]
    fn test_prune_merkle_tree_stores() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut state = PersistentState::open(
            db_path.path(),
            None,
            ChainId::default(),
            address::testing::nam(),
            Some(5),
            is_key_diff_storable,
        );
        let new_epoch_start = BlockHeight(1);
        let signed_root_key = bridge_pool::get_signed_root_key();
        // the first nonce isn't written for a test skipping pruning
        let nonce = Uint::default();

        state
            .in_mem_mut()
            .begin_block(new_epoch_start)
            .expect("begin_block failed");

        let key = ibc_key("key").unwrap();
        let value: u64 = 1;
        state.db_write(&key, encode(&value)).expect("write failed");

        state
            .in_mem_mut()
            .block
            .pred_epochs
            .new_epoch(new_epoch_start);

        state.commit_block().expect("commit failed");

        let new_epoch_start = BlockHeight(6);
        state
            .in_mem_mut()
            .begin_block(new_epoch_start)
            .expect("begin_block failed");

        let key = ibc_key("key2").unwrap();
        let value: u64 = 2;
        state.db_write(&key, encode(&value)).expect("write failed");

        // the second nonce isn't written for a test skipping pruning
        let nonce = nonce + 1;

        state.in_mem_mut().block.epoch = state.in_mem().block.epoch.next();
        state
            .in_mem_mut()
            .block
            .pred_epochs
            .new_epoch(new_epoch_start);

        state.commit_block().expect("commit failed");

        let result = state.get_merkle_tree(1.into(), Some(StoreType::Ibc));
        assert!(result.is_ok(), "The tree at Height 1 should be restored");

        let new_epoch_start = BlockHeight(11);
        state
            .in_mem_mut()
            .begin_block(new_epoch_start)
            .expect("begin_block failed");

        let nonce = nonce + 1;
        let root_proof =
            BridgePoolRootProof::new((KeccakHash::default(), nonce));
        let bytes = encode(&root_proof);
        state.db_write(&signed_root_key, bytes).unwrap();

        state.in_mem_mut().block.epoch = state.in_mem().block.epoch.next();
        state
            .in_mem_mut()
            .block
            .pred_epochs
            .new_epoch(new_epoch_start);

        state.commit_block().expect("commit failed");

        let result = state.get_merkle_tree(1.into(), Some(StoreType::Ibc));
        assert!(result.is_err(), "The tree at Height 1 should be pruned");
        let result = state.get_merkle_tree(5.into(), Some(StoreType::Ibc));
        assert!(
            result.is_err(),
            "The tree at Height 5 shouldn't be able to be restored"
        );
        let result = state.get_merkle_tree(6.into(), Some(StoreType::Ibc));
        assert!(result.is_ok(), "The ibc tree should be restored");
        let result =
            state.get_merkle_tree(6.into(), Some(StoreType::BridgePool));
        assert!(result.is_ok(), "The bridge pool tree should be restored");

        state
            .in_mem_mut()
            .begin_block(BlockHeight(12))
            .expect("begin_block failed");

        let nonce = nonce + 1;
        let root_proof =
            BridgePoolRootProof::new((KeccakHash::default(), nonce));
        let bytes = encode(&root_proof);
        state.db_write(&signed_root_key, bytes).unwrap();
        state.in_mem_mut().block.epoch = state.in_mem().block.epoch.next();
        state
            .in_mem_mut()
            .block
            .pred_epochs
            .new_epoch(BlockHeight(12));

        state.commit_block().expect("commit failed");

        // ibc tree should be able to be restored
        let result = state.get_merkle_tree(6.into(), Some(StoreType::Ibc));
        assert!(result.is_ok(), "The ibc tree should be restored");
        // bridge pool tree should be pruned because of the nonce
        let result =
            state.get_merkle_tree(6.into(), Some(StoreType::BridgePool));
        assert!(result.is_err(), "The bridge pool tree should be pruned");

        let result = state.get_merkle_tree(10.into(), Some(StoreType::NoDiff));
        assert!(result.is_err(), "The tree at Height 10 should be pruned");
        let result = state.get_merkle_tree(11.into(), Some(StoreType::NoDiff));
        assert!(result.is_ok(), "The tree at Height 11 should be restored");
    }

    /// Test the prefix iterator with RocksDB.
    #[test]
    fn test_persistent_storage_prefix_iter() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut state = PersistentState::open(
            db_path.path(),
            None,
            ChainId::default(),
            address::testing::nam(),
            None,
            is_key_diff_storable,
        );

        let prefix = storage::Key::parse("prefix").unwrap();
        let mismatched_prefix = storage::Key::parse("different").unwrap();
        // We'll write sub-key in some random order to check prefix iter's order
        let sub_keys = [2_i32, -1, 260, -2, 5, 0];

        for i in sub_keys.iter() {
            let key = prefix.push(i).unwrap();
            state.write(&key, i).unwrap();

            let key = mismatched_prefix.push(i).unwrap();
            state.write(&key, i / 2).unwrap();
        }

        // Then try to iterate over their prefix
        let iter = state::iter_prefix(&state, prefix.clone())
            .unwrap()
            .map(Result::unwrap);

        // The order has to be sorted by sub-key value
        let expected = sub_keys
            .iter()
            .sorted()
            .map(|i| (prefix.push(i).unwrap(), *i));
        itertools::assert_equal(iter, expected.clone());

        // Commit genesis state
        state.commit_block().unwrap();

        // Again, try to iterate over their prefix
        let iter = state::iter_prefix(&state, prefix.clone())
            .unwrap()
            .map(Result::unwrap);
        itertools::assert_equal(iter, expected);

        let more_sub_keys = [1_i32, i32::MIN, -10, 123, i32::MAX, 10];
        debug_assert!(
            !more_sub_keys.iter().any(|x| sub_keys.contains(x)),
            "assuming no repetition"
        );
        for i in more_sub_keys.iter() {
            let key = prefix.push(i).unwrap();
            state.write(&key, i).unwrap();

            let key = mismatched_prefix.push(i).unwrap();
            state.write(&key, i / 2).unwrap();
        }

        let iter = state::iter_prefix(&state, prefix.clone())
            .unwrap()
            .map(Result::unwrap);

        // The order has to be sorted by sub-key value
        let merged = itertools::merge(sub_keys.iter(), more_sub_keys.iter());
        let expected = merged
            .clone()
            .sorted()
            .map(|i| (prefix.push(i).unwrap(), *i));
        itertools::assert_equal(iter, expected);

        // Delete some keys
        let delete_keys = [2, 0, -10, 123];
        for i in delete_keys.iter() {
            let key = prefix.push(i).unwrap();
            state.delete(&key).unwrap()
        }

        // Check that iter_prefix doesn't return deleted keys anymore
        let iter = state::iter_prefix(&state, prefix.clone())
            .unwrap()
            .map(Result::unwrap);
        let expected = merged
            .filter(|x| !delete_keys.contains(x))
            .sorted()
            .map(|i| (prefix.push(i).unwrap(), *i));
        itertools::assert_equal(iter, expected.clone());

        // Commit genesis state
        state.commit_block().unwrap();

        // And check again
        let iter = state::iter_prefix(&state, prefix.clone())
            .unwrap()
            .map(Result::unwrap);
        itertools::assert_equal(iter, expected);
    }

    fn test_key_1() -> Key {
        Key::parse("testing1").unwrap()
    }

    fn test_key_2() -> Key {
        Key::parse("testing2").unwrap()
    }

    #[test]
    fn test_persistent_storage_writing_without_merklizing_or_diffs() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut state = PersistentState::open(
            db_path.path(),
            None,
            ChainId::default(),
            address::testing::nam(),
            None,
            // Only merkelize and persist diffs for `test_key_1`
            |key: &Key| -> bool { key == &test_key_1() },
        );
        // Start the first block
        let first_height = BlockHeight::first();
        state.in_mem_mut().block.height = first_height;

        let key1 = test_key_1();
        let val1 = 1u64;
        let key2 = test_key_2();
        let val2 = 2u64;

        // Standard write of key-val-1
        state.write(&key1, val1).unwrap();

        // Read from TestState should return val1
        let res = state.read::<u64>(&key1).unwrap().unwrap();
        assert_eq!(res, val1);

        // Read from Storage shouldn't return val1 because the block hasn't been
        // committed
        let (res, _) = state.db_read(&key1).unwrap();
        assert!(res.is_none());

        // Write key-val-2 without merklizing or diffs
        state.write(&key2, val2).unwrap();

        // Read from TestState should return val2
        let res = state.read::<u64>(&key2).unwrap().unwrap();
        assert_eq!(res, val2);

        // Commit block and storage changes
        state.pre_commit_block().unwrap();
        state.commit_block().unwrap();
        state.in_mem_mut().block.height =
            state.in_mem_mut().block.height.next_height();
        let second_height = state.in_mem().block.height;

        // Read key1 from Storage should return val1
        let (res1, _) = state.db_read(&key1).unwrap();
        let res1 = u64::try_from_slice(&res1.unwrap()).unwrap();
        assert_eq!(res1, val1);

        // Check merkle tree inclusion of key-val-1 explicitly
        let is_merklized1 = state.in_mem().block.tree.has_key(&key1).unwrap();
        assert!(is_merklized1);

        // Key2 should be in storage. Confirm by reading from
        // TestState and also by reading Storage subspace directly
        let res2 = state.read::<u64>(&key2).unwrap().unwrap();
        assert_eq!(res2, val2);
        let res2 = state.db().read_subspace_val(&key2).unwrap().unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);

        // Check explicitly that key-val-2 is not in merkle tree
        let is_merklized2 = state.in_mem().block.tree.has_key(&key2).unwrap();
        assert!(!is_merklized2);

        // Check that the proper diffs exist for key-val-1
        let res1 = state
            .db()
            .read_diffs_val(&key1, first_height, true)
            .unwrap();
        assert!(res1.is_none());

        let res1 = state
            .db()
            .read_diffs_val(&key1, first_height, false)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        // Check that there are diffs for key-val-2 in block 0, since all keys
        // need to have diffs for at least 1 block for rollback purposes
        let res2 = state
            .db()
            .read_rollback_val(&key2, first_height, true)
            .unwrap();
        assert!(res2.is_none());
        let res2 = state
            .db()
            .read_rollback_val(&key2, first_height, false)
            .unwrap()
            .unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);

        // Delete the data then commit the block
        state.delete(&key1).unwrap();
        state.delete(&key2).unwrap();
        state.pre_commit_block().unwrap();
        state.commit_block().unwrap();
        state.in_mem_mut().block.height =
            state.in_mem().block.height.next_height();

        // Check the key-vals are removed from the storage subspace
        let res1 = state.read::<u64>(&key1).unwrap();
        let res2 = state.read::<u64>(&key2).unwrap();
        assert!(res1.is_none() && res2.is_none());
        let res1 = state.db().read_subspace_val(&key1).unwrap();
        let res2 = state.db().read_subspace_val(&key2).unwrap();
        assert!(res1.is_none() && res2.is_none());

        // Check that the key-vals don't exist in the merkle tree anymore
        let is_merklized1 = state.in_mem().block.tree.has_key(&key1).unwrap();
        let is_merklized2 = state.in_mem().block.tree.has_key(&key2).unwrap();
        assert!(!is_merklized1 && !is_merklized2);

        // Check that key-val-1 diffs are properly updated for blocks 0 and 1
        let res1 = state
            .db()
            .read_diffs_val(&key1, first_height, true)
            .unwrap();
        assert!(res1.is_none());

        let res1 = state
            .db()
            .read_diffs_val(&key1, first_height, false)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        let res1 = state
            .db()
            .read_diffs_val(&key1, second_height, true)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        let res1 = state
            .db()
            .read_diffs_val(&key1, second_height, false)
            .unwrap();
        assert!(res1.is_none());

        // Check that key-val-2 diffs don't exist for block 0 anymore
        let res2 = state
            .db()
            .read_rollback_val(&key2, first_height, true)
            .unwrap();
        assert!(res2.is_none());
        let res2 = state
            .db()
            .read_rollback_val(&key2, first_height, false)
            .unwrap();
        assert!(res2.is_none());

        // Check that the block 1 diffs for key-val-2 include an "old" value of
        // val2 and no "new" value
        let res2 = state
            .db()
            .read_rollback_val(&key2, second_height, true)
            .unwrap()
            .unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);
        let res2 = state
            .db()
            .read_rollback_val(&key2, second_height, false)
            .unwrap();
        assert!(res2.is_none());
    }
}
