//! Tools for migrating shielded wallets .
//!
//! Since users store a serialized version of  [`ShieldedWallet`] locally,
//! changes to this type breaks backwards compatability if migrations are not
//! present.

use namada_core::borsh::{BorshDeserialize, BorshSerialize};

use crate::ShieldedWallet;
use crate::masp::ShieldedUtils;

/// An enum that adds version info to the [`ShieldedWallet`]
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum VersionedWallet<U: ShieldedUtils> {
    /// Version 0
    V0(v0::ShieldedWallet<U>),
    /// Version 1
    V1(v1::ShieldedWallet<U>),
    /// Version 2
    V2(ShieldedWallet<U>),
}

impl<U: ShieldedUtils> VersionedWallet<U> {
    /// Try to migrate this wallet to the latest version and return
    /// it if successful.
    pub fn migrate(self) -> eyre::Result<ShieldedWallet<U>> {
        match self {
            VersionedWallet::V0(w) => Ok(w.into()),
            VersionedWallet::V1(w) => Ok(w.into()),
            VersionedWallet::V2(w) => Ok(w),
        }
    }
}

/// A borrowed version of [`VersionedWallet`]
#[derive(BorshSerialize, Debug)]
pub enum VersionedWalletRef<'w, U: ShieldedUtils> {
    /// Version 0
    V0(&'w v0::ShieldedWallet<U>),
    /// Version 1
    V1(&'w v1::ShieldedWallet<U>),
    /// Version 2
    V2(&'w ShieldedWallet<U>),
}

mod migrations {
    use std::collections::{BTreeMap, BTreeSet};

    use masp_primitives::merkle_tree::CommitmentTree;
    use masp_primitives::sapling::{
        Diversifier, Node, Note, SAPLING_COMMITMENT_TREE_DEPTH,
    };
    use namada_core::collections::HashMap;

    use crate::masp::bridge_tree::pkg::{Level, Position, Source};
    use crate::masp::bridge_tree::{BridgeTree, InnerBridgeTree};
    use crate::masp::shielded_wallet::CompactNote;
    use crate::masp::{NotePosition, WitnessMap};

    #[allow(missing_docs, dead_code)]
    pub fn migrate_note_map(
        note_map: HashMap<usize, Note>,
        mut div_map: HashMap<usize, Diversifier>,
    ) -> HashMap<NotePosition, CompactNote> {
        let mut migrated = HashMap::new();

        for (pos, note) in note_map {
            let diversifier = div_map
                .swap_remove(&pos)
                .expect("Missing diversifier in shielded wallet");

            let Note {
                asset_type,
                value,
                pk_d,
                rseed,
                ..
            } = note;

            migrated.insert(
                NotePosition(pos.try_into().unwrap()),
                CompactNote {
                    asset_type,
                    value,
                    diversifier,
                    pk_d,
                    rseed,
                },
            );
        }

        migrated
    }

    #[allow(missing_docs, dead_code)]
    pub fn migrate_bridge_tree(
        tree: &CommitmentTree<Node>,
        witness_map: &WitnessMap,
    ) -> BridgeTree {
        let witness_map = {
            let mut map: HashMap<Position, _> = witness_map
                .iter()
                .map(|(pos, wit)| {
                    ((*pos).into(), wit.clone().into_incrementalmerkletree())
                })
                .collect();
            map.sort_unstable_keys();
            map
        };

        let frontier = tree
            .clone()
            .into_incrementalmerkletree()
            .to_frontier()
            .take();

        let prior_bridges: Vec<_> = witness_map
            .values()
            .map(|wit| wit.tree().to_frontier().take().unwrap())
            .collect();

        let tracking: BTreeSet<_> = prior_bridges
            .iter()
            .flat_map(|prior_bridge_frontier| {
                prior_bridge_frontier
                    .position()
                    .witness_addrs(Level::from(
                        SAPLING_COMMITMENT_TREE_DEPTH as u8,
                    ))
                    .filter_map(|(addr, source)| {
                        if source == Source::Future {
                            Some(addr)
                        } else {
                            None
                        }
                    })
            })
            .collect();

        let ommers: BTreeMap<_, _> = prior_bridges
            .iter()
            .map(|prior_bridge_frontier| {
                let position = prior_bridge_frontier.position();

                position
                    .witness_addrs(Level::from(
                        SAPLING_COMMITMENT_TREE_DEPTH as u8,
                    ))
                    .filter_map(|(addr, source)| {
                        if source == Source::Future {
                            Some(addr)
                        } else {
                            None
                        }
                    })
                    .zip(witness_map[&position].filled().iter().cloned())
                    .collect::<BTreeMap<_, _>>()
            })
            .reduce(|mut this, mut other| {
                this.append(&mut other);
                this
            })
            .unwrap_or_default();

        let mut tree: BridgeTree = InnerBridgeTree::from_parts(
            frontier,
            prior_bridges,
            tracking,
            ommers,
        )
        .unwrap()
        .into();

        tree.as_mut().garbage_collect_ommers();
        tree
    }

    #[cfg(test)]
    #[test]
    fn test_bridge_tree_migrations() {
        use masp_primitives::merkle_tree::IncrementalWitness;

        use crate::masp::NotePosition;

        let mut tree: CommitmentTree<Node> = CommitmentTree::empty();
        let mut witness_map = WitnessMap::new();

        // build commitment tree and witness map incrementally
        for i in 0u64..10 {
            let node = Node::from_scalar(i.into());

            tree.append(node).unwrap();

            for wit in witness_map.values_mut() {
                wit.append(node).unwrap();
            }

            if i % 2 == 0 {
                witness_map
                    .insert(i.into(), IncrementalWitness::from_tree(&tree));
            }
        }

        // convert to bridge tree
        let bridge_tree = migrate_bridge_tree(&tree, &witness_map);

        // check if roots and merkle proofs match
        assert_eq!(tree.root(), bridge_tree.as_ref().root());

        for i in (0u64..10).filter(|&i| i % 2 == 0) {
            assert_eq!(
                witness_map[&NotePosition::from(i)].path(),
                bridge_tree.witness(i)
            );
        }
    }
}

pub mod v0 {
    //! Version 0 of the shielded wallet, which is used for migration purposes.

    use std::collections::{BTreeMap, BTreeSet};

    use masp_primitives::asset_type::AssetType;
    use masp_primitives::memo::MemoBytes;
    use masp_primitives::merkle_tree::CommitmentTree;
    use masp_primitives::sapling::{
        Diversifier, Node, Note, Nullifier, ViewingKey,
    };
    use namada_core::borsh::{BorshDeserialize, BorshSerialize};
    use namada_core::collections::{HashMap, HashSet};
    use namada_core::masp::AssetData;

    use crate::masp::utils::MaspIndexedTx;
    use crate::masp::{
        ContextSyncStatus, NoteIndex, ShieldedUtils, WitnessMap,
    };

    #[derive(BorshSerialize, BorshDeserialize, Debug)]
    #[allow(missing_docs)]
    pub struct ShieldedWallet<U: ShieldedUtils> {
        /// Location where this shielded context is saved
        #[borsh(skip)]
        pub utils: U,
        /// The commitment tree produced by scanning all transactions up to
        /// tx_pos
        pub tree: CommitmentTree<Node>,
        /// Maps viewing keys to the block height to which they are synced.
        /// In particular, the height given by the value *has been scanned*.
        pub vk_heights: BTreeMap<ViewingKey, Option<MaspIndexedTx>>,
        /// Maps viewing keys to applicable note positions
        pub pos_map: HashMap<ViewingKey, BTreeSet<usize>>,
        /// Maps a nullifier to the note position to which it applies
        pub nf_map: HashMap<Nullifier, usize>,
        /// Maps note positions to their corresponding notes
        pub note_map: HashMap<usize, Note>,
        /// Maps note positions to their corresponding memos
        pub memo_map: HashMap<usize, MemoBytes>,
        /// Maps note positions to the diversifier of their payment address
        pub div_map: HashMap<usize, Diversifier>,
        /// Maps note positions to their witness (used to make merkle paths)
        pub witness_map: WitnessMap,
        /// The set of note positions that have been spent
        pub spents: HashSet<usize>,
        /// Maps asset types to their decodings
        pub asset_types: HashMap<AssetType, AssetData>,
        /// Maps note positions to their corresponding viewing keys
        pub vk_map: HashMap<usize, ViewingKey>,
        /// Maps a shielded tx to the index of its first output note.
        pub note_index: NoteIndex,
        /// The sync state of the context
        pub sync_status: ContextSyncStatus,
    }

    impl<U: ShieldedUtils + Default> Default for ShieldedWallet<U> {
        fn default() -> ShieldedWallet<U> {
            ShieldedWallet::<U> {
                utils: U::default(),
                vk_heights: BTreeMap::new(),
                note_index: BTreeMap::default(),
                tree: CommitmentTree::empty(),
                pos_map: HashMap::default(),
                nf_map: HashMap::default(),
                note_map: HashMap::default(),
                memo_map: HashMap::default(),
                div_map: HashMap::default(),
                witness_map: HashMap::default(),
                spents: HashSet::default(),
                asset_types: HashMap::default(),
                vk_map: HashMap::default(),
                sync_status: ContextSyncStatus::Confirmed,
            }
        }
    }

    impl<U: ShieldedUtils> From<ShieldedWallet<U>> for super::ShieldedWallet<U> {
        fn from(wallet: ShieldedWallet<U>) -> Self {
            #[cfg(not(feature = "historic"))]
            {
                use super::migrations;
                use crate::masp::NotePosition;

                Self {
                    utils: wallet.utils,
                    tree: migrations::migrate_bridge_tree(
                        &wallet.tree,
                        &wallet.witness_map,
                    ),
                    synced_height: wallet
                        .vk_heights
                        .into_values()
                        .filter_map(|itx| Some(itx?.indexed_tx.block_height))
                        .max()
                        .unwrap_or_default(),
                    pos_map: wallet
                        .pos_map
                        .into_iter()
                        .map(|(vk, positions)| {
                            (
                                vk,
                                positions
                                    .into_iter()
                                    .map(|pos| {
                                        NotePosition(pos.try_into().unwrap())
                                    })
                                    .collect(),
                            )
                        })
                        .collect(),
                    nf_map: wallet
                        .nf_map
                        .into_iter()
                        .map(|(nf, pos)| {
                            (nf, NotePosition(pos.try_into().unwrap()))
                        })
                        .collect(),
                    note_map: migrations::migrate_note_map(
                        wallet.note_map,
                        wallet.div_map,
                    ),
                    memo_map: wallet
                        .memo_map
                        .into_iter()
                        .map(|(pos, memo)| {
                            (NotePosition(pos.try_into().unwrap()), memo)
                        })
                        .collect(),
                    spents: wallet
                        .spents
                        .into_iter()
                        .map(|pos| NotePosition(pos.try_into().unwrap()))
                        .collect(),
                    asset_types: wallet.asset_types,
                    conversions: Default::default(),
                    note_index: wallet.note_index,
                    sync_status: wallet.sync_status,
                }
            }
            #[cfg(feature = "historic")]
            {
                drop(wallet);

                // NB: Need to return an empty wallet because
                // we can not rebuild the shielded history.
                Default::default()
            }
        }
    }
}

pub mod v1 {
    //! Version 1 of the shielded wallet, which is used for migration purposes.

    #![allow(missing_docs)]

    use std::collections::{BTreeMap, BTreeSet};

    use masp_primitives::asset_type::AssetType;
    use masp_primitives::memo::MemoBytes;
    use masp_primitives::merkle_tree::CommitmentTree;
    use masp_primitives::sapling::{
        Diversifier, Node, Note, Nullifier, ViewingKey,
    };
    use namada_core::borsh::{BorshDeserialize, BorshSerialize};
    use namada_core::collections::{HashMap, HashSet};
    use namada_core::masp::AssetData;

    use crate::masp::shielded_wallet::EpochedConversions;
    use crate::masp::utils::MaspIndexedTx;
    use crate::masp::{
        ContextSyncStatus, NoteIndex, ShieldedUtils, WitnessMap,
    };

    #[derive(BorshSerialize, BorshDeserialize, Debug)]
    pub struct ShieldedWallet<U: ShieldedUtils> {
        #[borsh(skip)]
        pub utils: U,
        pub tree: CommitmentTree<Node>,
        pub vk_heights: BTreeMap<ViewingKey, Option<MaspIndexedTx>>,
        pub pos_map: HashMap<ViewingKey, BTreeSet<usize>>,
        pub nf_map: HashMap<Nullifier, usize>,
        pub note_map: HashMap<usize, Note>,
        pub memo_map: HashMap<usize, MemoBytes>,
        pub div_map: HashMap<usize, Diversifier>,
        pub witness_map: WitnessMap,
        pub spents: HashSet<usize>,
        pub asset_types: HashMap<AssetType, AssetData>,
        pub conversions: EpochedConversions,
        pub vk_map: HashMap<usize, ViewingKey>,
        pub note_index: NoteIndex,
        pub sync_status: ContextSyncStatus,
    }

    impl<U: ShieldedUtils + Default> Default for ShieldedWallet<U> {
        fn default() -> ShieldedWallet<U> {
            ShieldedWallet::<U> {
                utils: U::default(),
                vk_heights: BTreeMap::new(),
                note_index: BTreeMap::default(),
                tree: CommitmentTree::empty(),
                pos_map: HashMap::default(),
                nf_map: HashMap::default(),
                note_map: HashMap::default(),
                memo_map: HashMap::default(),
                div_map: HashMap::default(),
                witness_map: HashMap::default(),
                spents: HashSet::default(),
                conversions: Default::default(),
                asset_types: HashMap::default(),
                vk_map: HashMap::default(),
                sync_status: ContextSyncStatus::Confirmed,
            }
        }
    }

    impl<U: ShieldedUtils> From<ShieldedWallet<U>> for super::ShieldedWallet<U> {
        fn from(wallet: ShieldedWallet<U>) -> Self {
            #[cfg(not(feature = "historic"))]
            {
                use super::migrations;
                use crate::masp::NotePosition;

                Self {
                    utils: wallet.utils,
                    tree: migrations::migrate_bridge_tree(
                        &wallet.tree,
                        &wallet.witness_map,
                    ),
                    synced_height: wallet
                        .vk_heights
                        .into_values()
                        .filter_map(|itx| Some(itx?.indexed_tx.block_height))
                        .max()
                        .unwrap_or_default(),
                    pos_map: wallet
                        .pos_map
                        .into_iter()
                        .map(|(vk, positions)| {
                            (
                                vk,
                                positions
                                    .into_iter()
                                    .map(|pos| {
                                        NotePosition(pos.try_into().unwrap())
                                    })
                                    .collect(),
                            )
                        })
                        .collect(),
                    nf_map: wallet
                        .nf_map
                        .into_iter()
                        .map(|(nf, pos)| {
                            (nf, NotePosition(pos.try_into().unwrap()))
                        })
                        .collect(),
                    note_map: migrations::migrate_note_map(
                        wallet.note_map,
                        wallet.div_map,
                    ),
                    memo_map: wallet
                        .memo_map
                        .into_iter()
                        .map(|(pos, memo)| {
                            (NotePosition(pos.try_into().unwrap()), memo)
                        })
                        .collect(),
                    spents: wallet
                        .spents
                        .into_iter()
                        .map(|pos| NotePosition(pos.try_into().unwrap()))
                        .collect(),
                    asset_types: wallet.asset_types,
                    conversions: wallet.conversions,
                    note_index: wallet.note_index,
                    sync_status: wallet.sync_status,
                }
            }
            #[cfg(feature = "historic")]
            {
                drop(wallet);

                // NB: Need to return an empty wallet because
                // we can not rebuild the shielded history.
                Default::default()
            }
        }
    }
}
