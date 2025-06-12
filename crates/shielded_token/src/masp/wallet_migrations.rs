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
    V1(ShieldedWallet<U>),
}

impl<U: ShieldedUtils> VersionedWallet<U> {
    /// Try to migrate this wallet to the latest version and return
    /// it if successful.
    pub fn migrate(self) -> eyre::Result<ShieldedWallet<U>> {
        match self {
            VersionedWallet::V0(w) => Ok(w.into()),
            VersionedWallet::V1(w) => Ok(w),
        }
    }
}

/// A borrowed version of [`VersionedWallet`]
#[derive(BorshSerialize, Debug)]
pub enum VersionedWalletRef<'w, U: ShieldedUtils> {
    /// Version 0
    V0(&'w v0::ShieldedWallet<U>),
    /// Version 1
    V1(&'w ShieldedWallet<U>),
}

/// Version 0 of the shielded wallet, which is used for migration purposes.
pub mod v0 {
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
    use namada_tx::IndexedTx;

    use crate::masp::shielded_wallet::TxHistoryEntry;
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
        /// The history of the applied shielded transactions (the failed ones
        /// won't show up in here). Only the sapling bundle data is
        /// cached here, for the transparent bundle data one should
        /// rely on querying a node or an indexer
        pub shielded_history:
            HashMap<ViewingKey, HashMap<IndexedTx, TxHistoryEntry>>,
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
                shielded_history: Default::default(),
                sync_status: ContextSyncStatus::Confirmed,
            }
        }
    }

    impl<U: ShieldedUtils> From<ShieldedWallet<U>> for super::ShieldedWallet<U> {
        fn from(wallet: ShieldedWallet<U>) -> Self {
            Self {
                utils: wallet.utils,
                tree: wallet.tree,
                vk_heights: wallet.vk_heights,
                pos_map: wallet.pos_map,
                nf_map: wallet.nf_map,
                note_map: wallet.note_map,
                memo_map: wallet.memo_map,
                div_map: wallet.div_map,
                witness_map: wallet.witness_map,
                spents: wallet.spents,
                asset_types: wallet.asset_types,
                conversions: Default::default(),
                vk_map: wallet.vk_map,
                note_index: wallet.note_index,
                sync_status: wallet.sync_status,
                shielded_history: wallet.shielded_history,
            }
        }
    }
}
