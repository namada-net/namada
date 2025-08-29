//! Bridge tree wrapper types to be used by the MASP.

pub use bridgetree as pkg; // Re-export the bridgetree crate as `pkg`.
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::{Node, SAPLING_COMMITMENT_TREE_DEPTH};
use namada_core::borsh::*;

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
    use std::collections::{BTreeMap, BTreeSet};

    use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};

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
