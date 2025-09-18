//! Bridge tree wrapper types to be used by the MASP.

use std::collections::{BTreeMap, BTreeSet};

pub use bridgetree as pkg; // Re-export the bridgetree crate as `pkg`.
use eyre::{Context, ContextCompat};
use masp_primitives::merkle_tree::{CommitmentTree, MerklePath};
use masp_primitives::sapling::{Node, SAPLING_COMMITMENT_TREE_DEPTH};
use namada_core::borsh::*;
use namada_core::collections::HashMap;

use self::pkg::{Address, Position};
use crate::masp::WitnessMap;

/// Inner type wrapped in [`BridgeTree`].
pub type InnerBridgeTree =
    bridgetree::BridgeTree<Node, { SAPLING_COMMITMENT_TREE_DEPTH as u8 }>;

/// Wrapper around a [`bridgetree::BridgeTree`].
#[derive(Debug, Eq, PartialEq, Clone, BorshSerialize, BorshDeserialize)]
pub struct BridgeTree(InnerBridgeTree);

impl AsRef<InnerBridgeTree> for BridgeTree {
    fn as_ref(&self) -> &InnerBridgeTree {
        &self.0
    }
}

impl AsMut<InnerBridgeTree> for BridgeTree {
    fn as_mut(&mut self) -> &mut InnerBridgeTree {
        &mut self.0
    }
}

impl Default for BridgeTree {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<InnerBridgeTree> for BridgeTree {
    fn from(inner: InnerBridgeTree) -> Self {
        Self(inner)
    }
}

impl BridgeTree {
    /// Create an empty [`BridgeTree`].
    pub const fn empty() -> Self {
        Self(bridgetree::BridgeTree::new())
    }

    /// Instantiate a [`BridgeTree`] from a [`CommitmentTree`] and
    /// [`WitnessMap`].
    ///
    /// Does not verify that each witness in the [`WitnessMap`] has the same
    /// root, nor does it check that these roots match that of the provided
    /// [`CommitmentTree`].
    pub fn from_tree_and_witness_map(
        tree: CommitmentTree<Node>,
        witness_map: WitnessMap,
    ) -> eyre::Result<Self> {
        let witness_map = {
            let mut map: HashMap<Position, _> = witness_map
                .into_iter()
                .map(|(pos, wit)| {
                    (pos.into(), wit.into_incrementalmerkletree())
                })
                .collect();
            map.sort_unstable_keys();
            map
        };

        let frontier = tree.into_incrementalmerkletree().to_frontier().take();
        let mut tracking = BTreeSet::new();
        let mut ommers = BTreeMap::new();
        let mut prior_bridges = Vec::with_capacity(witness_map.len());

        for (position, inc_witness) in witness_map {
            let mut next_incomplete_parent =
                Address::from(position).current_incomplete();

            for ommer in inc_witness.filled().iter().copied() {
                let ommer_addr = {
                    let next = next_incomplete_parent;

                    next_incomplete_parent =
                        next_incomplete_parent.next_incomplete_parent();

                    next.sibling()
                };
                ommers.insert(ommer_addr, ommer);
            }

            if next_incomplete_parent.level()
                < (SAPLING_COMMITMENT_TREE_DEPTH as u8).into()
            {
                tracking.insert(next_incomplete_parent);
            }

            prior_bridges.push(
                inc_witness
                    .tree()
                    .to_frontier()
                    .take()
                    .context("IncrementalWitness with empty commitment tree")?,
            );
        }

        Ok(InnerBridgeTree::from_parts(
            frontier,
            prior_bridges,
            tracking,
            ommers,
        )
        .context("Failed to create InnerBridgeTree from constituent parts")?
        .into())
    }

    /// Witness the node at `node_pos`.
    ///
    /// Returns a proof targeting the latest anchor in this tree.
    pub fn witness(
        &self,
        node_pos: impl TryInto<u64>,
    ) -> Option<MerklePath<Node>> {
        let position = bridgetree::Position::from(node_pos.try_into().ok()?);

        Some(
            self.as_ref()
                .witness(position)
                .ok()?
                .into_iter()
                .fold(
                    (
                        MerklePath::from_path(
                            Vec::with_capacity(SAPLING_COMMITMENT_TREE_DEPTH),
                            position.into(),
                        ),
                        bridgetree::Address::from(position),
                    ),
                    |(mut merkle_path, addr), node| {
                        merkle_path
                            .auth_path
                            .push((node, addr.is_right_child()));
                        (merkle_path, addr.parent())
                    },
                )
                .0,
        )
    }
}

#[cfg(test)]
mod tests {
    use masp_primitives::merkle_tree::IncrementalWitness;

    use super::*;

    #[test]
    fn test_bridge_tree_same_anchor_as_cmt_tree() {
        let mut legacy_witnesses: BTreeMap<u64, IncrementalWitness<Node>> =
            BTreeMap::new();
        let mut legacy_tree = CommitmentTree::empty();
        let mut tree = BridgeTree::empty();

        let nodes_to_witness = BTreeSet::from([0u64, 3u64, 5u64]);

        // build witnesses
        for node_pos in 0u64..10 {
            let node = Node::from_scalar(node_pos.into());

            tree.as_mut().append(node).unwrap();
            assert!(legacy_tree.append(node).is_ok());

            for wit in legacy_witnesses.values_mut() {
                assert!(wit.append(node).is_ok());
            }

            if nodes_to_witness.contains(&node_pos) {
                assert!(tree.as_mut().mark().is_some());
                legacy_witnesses.insert(
                    node_pos,
                    IncrementalWitness::from_tree(&legacy_tree),
                );
            }
        }

        // compare roots
        {
            let root = legacy_tree.root();

            assert_eq!(root, tree.as_ref().root());

            for wit in legacy_witnesses.values() {
                assert_eq!(root, wit.root());
            }
        }

        // compare witnesses
        let merkle_proofs_from_bridge_tree: BTreeMap<_, _> = nodes_to_witness
            .iter()
            .copied()
            .map(|node_pos| (node_pos, tree.witness(node_pos).unwrap()))
            .collect();
        let merkle_proofs_from_legacy_witnesses: BTreeMap<_, _> =
            legacy_witnesses
                .into_iter()
                .map(|(node_pos, witness)| (node_pos, witness.path().unwrap()))
                .collect();

        assert_eq!(
            merkle_proofs_from_bridge_tree,
            merkle_proofs_from_legacy_witnesses
        );
    }
}
