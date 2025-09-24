//! Helper functions and types
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::{Bound, RangeBounds};

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::memo::MemoBytes;
use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::{Node, Note, PaymentAddress, ViewingKey};
use masp_primitives::transaction::Transaction;
use namada_core::chain::BlockHeight;
use namada_core::collections::HashMap;
use namada_state::TxIndex;
use namada_tx::IndexedTx;
use namada_tx::event::MaspEventKind;
use serde::{Deserialize, Serialize};

use crate::masp::NotePosition;

/// The type of a MASP transaction
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    PartialOrd,
    PartialEq,
    Eq,
    Ord,
    Serialize,
    Deserialize,
    Hash,
)]
pub enum MaspTxKind {
    /// A MASP transaction used for fee payment
    FeePayment,
    /// A general MASP transfer
    #[default]
    Transfer,
}

impl From<MaspEventKind> for MaspTxKind {
    fn from(value: MaspEventKind) -> Self {
        match value {
            MaspEventKind::FeePayment => Self::FeePayment,
            MaspEventKind::Transfer => Self::Transfer,
        }
    }
}

/// An indexed masp tx carrying information on whether it was a fee paying tx or
/// a normal transfer
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Hash,
)]
pub struct MaspIndexedTx {
    /// The masp tx kind, fee-payment or transfer
    pub kind: MaspTxKind,
    /// The pointer to the inner tx carrying this masp tx
    pub indexed_tx: IndexedTx,
}

impl Ord for MaspIndexedTx {
    fn cmp(&self, other: &Self) -> Ordering {
        // If txs are in different blocks we just have to compare their block
        // heights. If instead txs are in the same block, masp fee paying txs
        // take precedence over transfer masp txs. After that we sort them based
        // on their indexes
        self.indexed_tx
            .block_height
            .cmp(&other.indexed_tx.block_height)
            .then(
                self.kind
                    .cmp(&other.kind)
                    .then(self.indexed_tx.cmp(&other.indexed_tx)),
            )
    }
}

impl PartialOrd for MaspIndexedTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Inclusive range of [`MaspIndexedTx`] entries.
pub struct MaspIndexedTxRange {
    lo: MaspIndexedTx,
    hi: MaspIndexedTx,
}

impl MaspIndexedTxRange {
    /// Create a new [`MaspIndexedTxRange`].
    pub const fn new(lo: MaspIndexedTx, hi: MaspIndexedTx) -> Self {
        Self { lo, hi }
    }

    /// Create a new [`MaspIndexedTxRange`] over a range of [block
    /// heights](BlockHeight).
    pub const fn between_heights(from: BlockHeight, to: BlockHeight) -> Self {
        Self::new(
            MaspIndexedTx {
                kind: MaspTxKind::FeePayment,
                indexed_tx: IndexedTx {
                    block_height: from,
                    block_index: TxIndex(0),
                    batch_index: None,
                },
            },
            MaspIndexedTx {
                kind: MaspTxKind::Transfer,
                indexed_tx: IndexedTx {
                    block_height: to,
                    block_index: TxIndex(u32::MAX),
                    batch_index: Some(u32::MAX),
                },
            },
        )
    }

    /// Create a new [`MaspIndexedTxRange`] over a given [`BlockHeight`].
    pub const fn with_height(height: BlockHeight) -> Self {
        Self::between_heights(height, height)
    }

    /// The start of the range.
    pub const fn start(&self) -> MaspIndexedTx {
        self.lo
    }

    /// The end of the range.
    pub const fn end(&self) -> MaspIndexedTx {
        self.hi
    }
}

impl RangeBounds<MaspIndexedTx> for MaspIndexedTxRange {
    fn start_bound(&self) -> Bound<&MaspIndexedTx> {
        Bound::Included(&self.lo)
    }

    fn end_bound(&self) -> Bound<&MaspIndexedTx> {
        Bound::Included(&self.hi)
    }

    fn contains<U>(&self, item: &U) -> bool
    where
        MaspIndexedTx: PartialOrd<U>,
        U: PartialOrd<MaspIndexedTx> + ?Sized,
    {
        *item >= self.lo && *item <= self.hi
    }
}

/// Type alias for convenience and profit
pub type IndexedNoteData = BTreeMap<MaspIndexedTx, Transaction>;

/// Type alias for the entries of [`IndexedNoteData`] iterators
pub type IndexedNoteEntry = (MaspIndexedTx, Transaction);

/// Borrowed version of an [`IndexedNoteEntry`]
pub type IndexedNoteEntryRefs<'a> = (&'a MaspIndexedTx, &'a Transaction);

/// Type alias for a successful note decryption.
pub type DecryptedData = (Note, PaymentAddress, MemoBytes);

/// Cache of decrypted notes.
#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct TrialDecrypted {
    inner: HashMap<
        MaspIndexedTx,
        HashMap<ViewingKey, BTreeMap<usize, DecryptedData>>,
    >,
}

impl TrialDecrypted {
    /// Returns the number of successful trial decryptions in cache.
    pub fn successful_decryptions(&self) -> usize {
        self.inner
            .values()
            .flat_map(|viewing_keys_to_notes| viewing_keys_to_notes.values())
            .map(|decrypted_notes| decrypted_notes.len())
            .sum::<usize>()
    }

    /// Get cached notes decrypted with `vk`, indexed at `itx`.
    pub fn get(
        &self,
        itx: &MaspIndexedTx,
        vk: &ViewingKey,
    ) -> Option<&BTreeMap<usize, DecryptedData>> {
        self.inner.get(itx).and_then(|h| h.get(vk))
    }

    /// Take cached notes decrypted with `vk`, indexed at `itx`.
    pub fn take(
        &mut self,
        itx: &MaspIndexedTx,
        vk: &ViewingKey,
    ) -> Option<BTreeMap<usize, DecryptedData>> {
        let (notes, no_more_notes) = {
            let viewing_keys_to_notes = self.inner.get_mut(itx)?;
            let notes = viewing_keys_to_notes.swap_remove(vk)?;
            (notes, viewing_keys_to_notes.is_empty())
        };
        if no_more_notes {
            self.inner.swap_remove(itx);
        }
        Some(notes)
    }

    /// Cache `notes` decrypted with `vk`, indexed at `itx`.
    pub fn insert(
        &mut self,
        itx: MaspIndexedTx,
        vk: ViewingKey,
        notes: BTreeMap<usize, DecryptedData>,
    ) {
        self.inner.entry(itx).or_default().insert(vk, notes);
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Check if the tx with  [`MaspIndexedTx`] was successfully decrypted
    pub fn decrypted_by_any_vk(&self, ix: &MaspIndexedTx) -> bool {
        self.inner.get(ix).is_some_and(|viewing_keys_to_notes| {
            viewing_keys_to_notes
                .values()
                .any(|decrypted_notes| !decrypted_notes.is_empty())
        })
    }
}

/// A cache of fetched indexed transactions.
///
/// An invariant that shielded-sync maintains is that
/// this cache either contains all transactions from
/// a given height, or none.
#[derive(Debug, Default, Clone, BorshSerialize, BorshDeserialize)]
pub struct Fetched {
    pub(crate) txs: IndexedNoteData,
}

impl Fetched {
    /// Append elements to the cache from an iterator.
    pub fn extend<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        self.txs.extend(items);
    }

    /// Iterates over the fetched transactions in the order
    /// they appear in blocks.
    pub fn iter(
        &self,
    ) -> impl IntoIterator<Item = IndexedNoteEntryRefs<'_>> + '_ {
        &self.txs
    }

    /// Iterates over the fetched transactions in the order
    /// they appear in blocks, whilst taking ownership of
    /// the returned data.
    pub fn take(&mut self) -> IndexedNoteData {
        std::mem::take(&mut self.txs)
    }

    /// Add a single entry to the cache.
    pub fn insert(&mut self, (k, v): IndexedNoteEntry) {
        self.txs.insert(k, v);
    }

    /// Check if this cache has already been populated for a given
    /// block height.
    pub fn contains_height(&self, height: BlockHeight) -> bool {
        self.txs
            .range(MaspIndexedTxRange::with_height(height))
            .next()
            .is_some()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Check the length of the fetched cache
    pub fn len(&self) -> usize {
        self.txs.len()
    }
}

impl IntoIterator for Fetched {
    type IntoIter = <IndexedNoteData as IntoIterator>::IntoIter;
    type Item = IndexedNoteEntry;

    fn into_iter(self) -> Self::IntoIter {
        self.txs.into_iter()
    }
}

/// When retrying to fetch all notes in a
/// loop, this dictates the strategy for
/// how many attempts should be made.
#[derive(Debug, Copy, Clone)]
pub enum RetryStrategy {
    /// Always retry
    Forever,
    /// Limit number of retries to a fixed number
    Times(u64),
}

impl RetryStrategy {
    /// Check if retries are exhausted.
    pub fn may_retry(&mut self) -> bool {
        match self {
            RetryStrategy::Forever => true,
            RetryStrategy::Times(left) => {
                if *left == 0 {
                    false
                } else {
                    *left -= 1;
                    true
                }
            }
        }
    }
}

/// Enumerates the capabilities of a [`MaspClient`] implementation.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct MaspClientCapabilities(u8);

impl MaspClientCapabilities {
    #[allow(missing_docs)]
    pub const MAY_FETCH_PRE_BUILT_NOTE_INDEX: Self = Self(0b00000010);
    #[allow(missing_docs)]
    pub const MAY_FETCH_PRE_BUILT_TREE: Self = Self(0b00000001);
    #[allow(missing_docs)]
    pub const MAY_FETCH_PRE_BUILT_WITNESS_MAP: Self = Self(0b00000100);
    #[allow(missing_docs)]
    pub const NONE: Self = Self(0);

    /// Add `other` to the current set of capabilities.
    pub const fn plus(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Subtract `other` from the current set of capabilities.
    pub const fn minus(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Check if `other` has a subset of the [`MaspClientCapabilities`] of
    /// `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Check whether there are no [`MaspClientCapabilities`].
    pub const fn are_none(self) -> bool {
        self.0 == 0
    }

    /// Check if the masp client is able to fetch a pre-built
    /// commitment tree.
    pub const fn may_fetch_pre_built_tree(&self) -> bool {
        self.0 & Self::MAY_FETCH_PRE_BUILT_TREE.0 != 0
    }

    /// Check if the masp client is able to fetch a pre-built
    /// note index.
    pub const fn may_fetch_pre_built_note_index(&self) -> bool {
        self.0 & Self::MAY_FETCH_PRE_BUILT_NOTE_INDEX.0 != 0
    }

    /// Check if the masp client is able to fetch a pre-built
    /// witness map.
    pub const fn may_fetch_pre_built_witness_map(&self) -> bool {
        self.0 & Self::MAY_FETCH_PRE_BUILT_WITNESS_MAP.0 != 0
    }
}

/// This abstracts away the implementation details
/// of how shielded-sync fetches the necessary data
/// from a remote server.
pub trait MaspClient: Clone {
    /// Error type returned by the methods of this trait
    type Error: std::error::Error + Send + Sync + 'static;

    /// Hint to this [`MaspClient`] implementation the block range
    /// that will be fetched.
    ///
    /// ## Use-case
    ///
    /// This function is primarily used to decide when it is optimal
    /// (latency wise) to fetch a block index (i.e. bloom filter) with
    /// the block heights that contain MASP txs.
    fn hint(&mut self, from: BlockHeight, to: BlockHeight);

    /// Return the last block height we can retrieve data from.
    #[allow(async_fn_in_trait)]
    async fn last_block_height(
        &self,
    ) -> Result<Option<BlockHeight>, Self::Error>;

    /// Fetch shielded transfers from blocks heights in the range `[from, to]`,
    /// keeping track of progress through `progress`. The fetched transfers
    /// are sent over to a separate worker through `tx_sender`.
    #[allow(async_fn_in_trait)]
    async fn fetch_shielded_transfers(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Self::Error>;

    /// Return the capabilities of this client.
    fn capabilities(&self) -> MaspClientCapabilities;

    /// Fetch the commitment tree of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_commitment_tree(
        &self,
        height: BlockHeight,
    ) -> Result<CommitmentTree<Node>, Self::Error>;

    /// Fetch the tx notes map of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_note_index(
        &self,
        height: BlockHeight,
    ) -> Result<BTreeMap<MaspIndexedTx, NotePosition>, Self::Error>;

    /// Fetch the witness map of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_witness_map(
        &self,
        height: BlockHeight,
    ) -> Result<HashMap<NotePosition, IncrementalWitness<Node>>, Self::Error>;

    /// Check whether the given commitment anchor exists
    #[allow(async_fn_in_trait)]
    async fn commitment_anchor_exists(
        &self,
        root: &Node,
    ) -> Result<bool, Self::Error>;
}

/// Given a block height range we wish to request and a cache of fetched block
/// heights, returns the set of sub-ranges we need to request so that all blocks
/// in the inclusive range `[from, to]` get cached.
pub fn blocks_left_to_fetch(
    from: BlockHeight,
    to: BlockHeight,
    fetched: &Fetched,
) -> Vec<[BlockHeight; 2]> {
    const ZERO: BlockHeight = BlockHeight(0);

    if from > to {
        panic!("Empty range passed to `blocks_left_to_fetch`, [{from}, {to}]");
    }
    if from == ZERO || to == ZERO {
        panic!("Block height values start at 1");
    }

    let mut to_fetch = Vec::with_capacity((to.0 - from.0 + 1) as usize);
    let mut current_from = from;
    let mut need_to_fetch = true;

    for height in (from.0..=to.0).map(BlockHeight) {
        let height_in_cache = fetched.contains_height(height);

        // cross an upper gap boundary
        if need_to_fetch && height_in_cache {
            if height > current_from {
                to_fetch.push([
                    current_from,
                    height.checked_sub(1).expect("Height is greater than zero"),
                ]);
            }
            need_to_fetch = false;
        } else if !need_to_fetch && !height_in_cache {
            // cross a lower gap boundary
            current_from = height;
            need_to_fetch = true;
        }
    }
    if need_to_fetch {
        to_fetch.push([current_from, to]);
    }
    to_fetch
}

#[cfg(test)]
mod test_blocks_left_to_fetch {
    use namada_state::TxIndex;
    use proptest::prelude::*;

    use super::*;
    use crate::masp::test_utils::arbitrary_masp_tx;

    struct ArbRange {
        max_from: u64,
        max_len: u64,
    }

    impl Default for ArbRange {
        fn default() -> Self {
            Self {
                max_from: u64::MAX,
                max_len: 1000,
            }
        }
    }

    fn fetched_cache_with_blocks(
        blocks_in_cache: impl IntoIterator<Item = BlockHeight>,
    ) -> Fetched {
        let masp_tx = arbitrary_masp_tx();

        let txs = blocks_in_cache
            .into_iter()
            .map(|height| {
                (
                    MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: height,
                            block_index: TxIndex(0),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    },
                    masp_tx.clone(),
                )
            })
            .collect();
        Fetched { txs }
    }

    fn blocks_in_range(
        from: BlockHeight,
        to: BlockHeight,
    ) -> impl Iterator<Item = BlockHeight> {
        (from.0..=to.0).map(BlockHeight)
    }

    prop_compose! {
        fn arb_block_range(ArbRange { max_from, max_len }: ArbRange)
        (
            from in 1u64..=max_from,
        )
        (
            from in Just(from),
            to in from..from.saturating_add(max_len)
        )
        -> (BlockHeight, BlockHeight)
        {
            (BlockHeight(from), BlockHeight(to))
        }
    }

    proptest! {
        #[test]
        fn test_empty_cache_with_singleton_output((from, to) in arb_block_range(ArbRange::default())) {
            let empty_cache = fetched_cache_with_blocks([]);

            let &[[returned_from, returned_to]] = blocks_left_to_fetch(
                from,
                to,
                &empty_cache,
            )
            .as_slice() else {
                return Err(TestCaseError::Fail("Test failed".into()));
            };

            prop_assert_eq!(returned_from, from);
            prop_assert_eq!(returned_to, to);
        }

        #[test]
        fn test_non_empty_cache_with_empty_output((from, to) in arb_block_range(ArbRange::default())) {
            let cache = fetched_cache_with_blocks(
                blocks_in_range(from, to)
            );

            let &[] = blocks_left_to_fetch(
                from,
                to,
                &cache,
            )
            .as_slice() else {
                return Err(TestCaseError::Fail("Test failed".into()));
            };
        }

        #[test]
        fn test_non_empty_cache_with_singleton_input_and_maybe_singleton_output(
            (from, to) in arb_block_range(ArbRange::default()),
            block_height in 1u64..1000,
        ) {
            test_non_empty_cache_with_singleton_input_and_maybe_singleton_output_inner(
                from,
                to,
                BlockHeight(block_height),
            )?;
        }

        #[test]
        fn test_non_empty_cache_with_singleton_hole_and_singleton_output(
            (first_from, first_to) in
                arb_block_range(ArbRange {
                    max_from: 1_000_000,
                    max_len: 1000,
                }),
        ) {
            // [from, to], [to + 2, 2 * to - from + 2]

            let hole = first_to + 1;
            let second_from = BlockHeight(first_to.0 + 2);
            let second_to = BlockHeight(2 * first_to.0 - first_from.0 + 2);

            let cache = fetched_cache_with_blocks(
                blocks_in_range(first_from, first_to)
                    .chain(blocks_in_range(second_from, second_to)),
            );

            let &[[returned_from, returned_to]] = blocks_left_to_fetch(
                first_from,
                second_to,
                &cache,
            )
            .as_slice() else {
                return Err(TestCaseError::Fail("Test failed".into()));
            };

            prop_assert_eq!(returned_from, hole);
            prop_assert_eq!(returned_to, hole);
        }
    }

    fn test_non_empty_cache_with_singleton_input_and_maybe_singleton_output_inner(
        from: BlockHeight,
        to: BlockHeight,
        block_height: BlockHeight,
    ) -> Result<(), TestCaseError> {
        let cache = fetched_cache_with_blocks(blocks_in_range(from, to));

        if block_height >= from && block_height <= to {
            // random height is inside the range of txs in cache

            let &[] = blocks_left_to_fetch(block_height, block_height, &cache)
                .as_slice()
            else {
                return Err(TestCaseError::Fail("Test failed".into()));
            };
        } else {
            // random height is outside the range of txs in cache

            let &[[returned_from, returned_to]] =
                blocks_left_to_fetch(block_height, block_height, &cache)
                    .as_slice()
            else {
                return Err(TestCaseError::Fail("Test failed".into()));
            };

            prop_assert_eq!(returned_from, block_height);
            prop_assert_eq!(returned_to, block_height);
        }

        Ok(())
    }

    #[test]
    fn test_happy_flow() {
        let cache = fetched_cache_with_blocks([
            BlockHeight(1),
            BlockHeight(5),
            BlockHeight(6),
            BlockHeight(8),
            BlockHeight(11),
        ]);

        let from = BlockHeight(1);
        let to = BlockHeight(10);

        let blocks_to_fetch = blocks_left_to_fetch(from, to, &cache);
        assert_eq!(
            &blocks_to_fetch,
            &[
                [BlockHeight(2), BlockHeight(4)],
                [BlockHeight(7), BlockHeight(7)],
                [BlockHeight(9), BlockHeight(10)],
            ],
        );
    }

    #[test]
    fn test_endpoint_cases() {
        let cache =
            fetched_cache_with_blocks(blocks_in_range(2.into(), 4.into()));
        let blocks_to_fetch = blocks_left_to_fetch(1.into(), 3.into(), &cache);
        assert_eq!(&blocks_to_fetch, &[[BlockHeight(1), BlockHeight(1)]]);

        // -------------

        let cache =
            fetched_cache_with_blocks(blocks_in_range(1.into(), 3.into()));
        let blocks_to_fetch = blocks_left_to_fetch(2.into(), 4.into(), &cache);
        assert_eq!(&blocks_to_fetch, &[[BlockHeight(4), BlockHeight(4)]]);

        // -------------

        let cache =
            fetched_cache_with_blocks(blocks_in_range(2.into(), 4.into()));
        let blocks_to_fetch = blocks_left_to_fetch(1.into(), 5.into(), &cache);
        assert_eq!(
            &blocks_to_fetch,
            &[
                [BlockHeight(1), BlockHeight(1)],
                [BlockHeight(5), BlockHeight(5)],
            ],
        );

        // -------------

        let cache =
            fetched_cache_with_blocks(blocks_in_range(1.into(), 5.into()));
        let blocks_to_fetch = blocks_left_to_fetch(2.into(), 4.into(), &cache);
        assert!(blocks_to_fetch.is_empty());
    }

    #[test]
    fn test_sort_indexed_masp_events() {
        let ev1 = MaspIndexedTx {
            kind: MaspTxKind::FeePayment,
            indexed_tx: IndexedTx {
                block_height: BlockHeight(1),
                block_index: TxIndex(2),
                batch_index: Some(0),
            },
        };
        let ev2 = MaspIndexedTx {
            kind: MaspTxKind::Transfer,
            indexed_tx: IndexedTx {
                block_height: BlockHeight(2),
                block_index: TxIndex(0),
                batch_index: Some(0),
            },
        };
        let ev3 = MaspIndexedTx {
            kind: MaspTxKind::Transfer,
            indexed_tx: IndexedTx {
                block_height: BlockHeight(3),
                block_index: TxIndex(1),
                batch_index: Some(1),
            },
        };
        let ev4 = MaspIndexedTx {
            kind: MaspTxKind::FeePayment,
            indexed_tx: IndexedTx {
                block_height: BlockHeight(3),
                block_index: TxIndex(3),
                batch_index: Some(2),
            },
        };
        let ev5 = MaspIndexedTx {
            kind: MaspTxKind::FeePayment,
            indexed_tx: IndexedTx {
                block_height: BlockHeight(3),
                block_index: TxIndex(2),
                batch_index: Some(0),
            },
        };
        let ev6 = MaspIndexedTx {
            kind: MaspTxKind::Transfer,
            indexed_tx: IndexedTx {
                block_height: BlockHeight(1),
                block_index: TxIndex(1),
                batch_index: Some(1),
            },
        };
        let ev7 = MaspIndexedTx {
            kind: MaspTxKind::Transfer,
            indexed_tx: IndexedTx {
                block_height: BlockHeight(1),
                block_index: TxIndex(1),
                batch_index: Some(0),
            },
        };

        let mut txs = [ev1, ev2, ev3, ev4, ev5, ev6, ev7];

        txs.sort();

        assert_eq!(txs, [ev1, ev7, ev6, ev2, ev5, ev4, ev3])
    }
}
