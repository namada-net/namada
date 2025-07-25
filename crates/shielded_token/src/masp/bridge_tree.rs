//! Bridge tree wrapper types to be used by the MASP.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Write};

pub use bridgetree as pkg; // Re-export the bridgetree crate as `pkg`.
use bridgetree::Hashable;
use masp_primitives::sapling::{Node, SAPLING_COMMITMENT_TREE_DEPTH};
use namada_core::borsh::*;

/// Inner type wrapped in [`BridgeTree`].
pub type InnerBridgeTree = bridgetree::BridgeTree<
    BridgeTreeNode,
    (),
    { SAPLING_COMMITMENT_TREE_DEPTH as u8 },
>;

/// Wrapper around a [`bridgetree::BridgeTree`].
#[derive(Debug, Eq, PartialEq, Clone)]
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

impl BridgeTree {
    /// Create an empty [`BridgeTree`].
    pub fn empty() -> Self {
        Self(bridgetree::BridgeTree::new(1))
    }
}

impl BorshSerialize for BridgeTree {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        fn serialize_usize_as_u32<W: Write>(
            x: usize,
            writer: &mut W,
        ) -> std::io::Result<()> {
            let x = u32::try_from(x).map_err(std::io::Error::other)?;
            BorshSerialize::serialize(&x, writer)
        }

        fn serialize_merkle_bridge<W: Write>(
            bridge: &bridgetree::MerkleBridge<BridgeTreeNode>,
            writer: &mut W,
        ) -> std::io::Result<()> {
            // Serialize prior_position
            BorshSerialize::serialize(
                &bridge.prior_position().map(u64::from),
                writer,
            )?;

            // Serialize tracking set
            serialize_usize_as_u32(bridge.tracking().len(), writer)?;
            for addr in bridge.tracking() {
                BorshSerialize::serialize(&u8::from(addr.level()), writer)?;
                BorshSerialize::serialize(&addr.index(), writer)?;
            }

            // Serialize ommers map
            serialize_usize_as_u32(bridge.ommers().len(), writer)?;
            for (addr, ommer) in bridge.ommers() {
                BorshSerialize::serialize(&u8::from(addr.level()), writer)?;
                BorshSerialize::serialize(&addr.index(), writer)?;
                BorshSerialize::serialize(ommer, writer)?;
            }

            // Serialize non-empty frontier using its parts
            let frontier = bridge.frontier();
            BorshSerialize::serialize(&u64::from(frontier.position()), writer)?;
            BorshSerialize::serialize(frontier.leaf(), writer)?;
            serialize_usize_as_u32(frontier.ommers().len(), writer)?;
            for ommer in frontier.ommers() {
                BorshSerialize::serialize(ommer, writer)?;
            }

            Ok(())
        }

        // Serialize `prior_bridges`
        serialize_usize_as_u32(self.0.prior_bridges().len(), writer)?;
        for prior_bridge in self.0.prior_bridges() {
            serialize_merkle_bridge(prior_bridge, writer)?;
        }

        // Serialize `current_bridge`
        BorshSerialize::serialize(&self.0.current_bridge().is_some(), writer)?;
        if let Some(current_bridge) = self.0.current_bridge() {
            serialize_merkle_bridge(current_bridge, writer)?;
        }

        Ok(())
    }
}

impl BorshDeserialize for BridgeTree {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        fn deserialize_u32_as_usize<R: Read>(
            reader: &mut R,
        ) -> std::io::Result<usize> {
            let x = u32::deserialize_reader(reader)?;
            usize::try_from(x).map_err(std::io::Error::other)
        }

        fn deserialize_merkle_bridge<R: Read>(
            reader: &mut R,
        ) -> std::io::Result<bridgetree::MerkleBridge<BridgeTreeNode>> {
            // Deserialize prior_position
            let prior_position = Option::<u64>::deserialize_reader(reader)?
                .map(bridgetree::Position::from);

            // Deserialize tracking set
            let tracking_len = deserialize_u32_as_usize(reader)?;
            let mut tracking = BTreeSet::new();
            for _ in 0..tracking_len {
                let level = u8::deserialize_reader(reader)?;
                let index = u64::deserialize_reader(reader)?;
                tracking.insert(bridgetree::Address::from_parts(
                    level.into(),
                    index,
                ));
            }

            // Deserialize ommers map
            let ommers_len = deserialize_u32_as_usize(reader)?;
            let mut ommers = BTreeMap::new();
            for _ in 0..ommers_len {
                let level = u8::deserialize_reader(reader)?;
                let index = u64::deserialize_reader(reader)?;
                let ommer = BridgeTreeNode::deserialize_reader(reader)?;
                ommers.insert(
                    bridgetree::Address::from_parts(level.into(), index),
                    ommer,
                );
            }

            // Deserialize non-empty frontier from its parts
            let frontier_position =
                bridgetree::Position::from(u64::deserialize_reader(reader)?);
            let frontier_leaf = BridgeTreeNode::deserialize_reader(reader)?;
            let frontier_ommers_len = deserialize_u32_as_usize(reader)?;
            let mut frontier_ommers = Vec::with_capacity(frontier_ommers_len);
            for _ in 0..frontier_ommers_len {
                frontier_ommers
                    .push(BridgeTreeNode::deserialize_reader(reader)?);
            }
            let frontier = bridgetree::NonEmptyFrontier::from_parts(
                frontier_position,
                frontier_leaf,
                frontier_ommers,
            )
            .map_err(|err| {
                std::io::Error::other(format!(
                    "failed to rebuild NonEmptyFrontier from deserialized \
                     data: {err:?}"
                ))
            })?;

            Ok(bridgetree::MerkleBridge::from_parts(
                prior_position,
                tracking,
                ommers,
                frontier,
            ))
        }

        // Deserialize `prior_bridges`
        let prior_bridges_len = deserialize_u32_as_usize(reader)?;
        let mut prior_bridges = Vec::with_capacity(prior_bridges_len);
        for _ in 0..prior_bridges_len {
            prior_bridges.push(deserialize_merkle_bridge(reader)?);
        }

        // Deserialize `current_bridge`
        let has_current_bridge = bool::deserialize_reader(reader)?;
        let current_bridge = if has_current_bridge {
            Some(deserialize_merkle_bridge(reader)?)
        } else {
            None
        };

        // Rebuild `saved` BTreeMap
        let saved = prior_bridges
            .iter()
            .enumerate()
            .map(|(index, bridge)| (bridge.position(), index))
            .collect();

        let tree = bridgetree::BridgeTree::from_parts(
            prior_bridges,
            current_bridge,
            saved,
            VecDeque::new(),
            1,
        )
        .map_err(|err| {
            std::io::Error::other(format!(
                "failed to rebuild BridgeTree from deserialized data: {err:?}"
            ))
        })?;

        Ok(BridgeTree(tree))
    }
}

/// Wrapper around a Sapling [`Node`] to be used by a [`BridgeTree`].
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Default,
)]
pub struct BridgeTreeNode(Node);

impl From<Node> for BridgeTreeNode {
    fn from(node: Node) -> Self {
        Self(node)
    }
}

impl From<BridgeTreeNode> for Node {
    fn from(node: BridgeTreeNode) -> Self {
        node.0
    }
}

impl Hashable for BridgeTreeNode {
    fn empty_leaf() -> Self {
        BridgeTreeNode(Node::empty_leaf())
    }

    fn combine(level: bridgetree::Level, a: &Self, b: &Self) -> Self {
        BridgeTreeNode(Node::combine(level, &a.0, &b.0))
    }

    fn empty_root(level: bridgetree::Level) -> Self {
        BridgeTreeNode(Node::empty_root(level))
    }
}

impl Ord for BridgeTreeNode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

impl PartialOrd for BridgeTreeNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_tree_borsh_roundtrip() {
        // build a dummy bridge tree
        let mut tree = BridgeTree::empty();

        assert!(tree.as_mut().append(Node::from_scalar(0u64.into()).into()));
        assert!(tree.as_mut().mark().is_some());
        assert!(tree.as_mut().append(Node::from_scalar(1u64.into()).into()));
        assert!(tree.as_mut().append(Node::from_scalar(2u64.into()).into()));
        assert!(tree.as_mut().append(Node::from_scalar(3u64.into()).into()));
        assert!(tree.as_mut().mark().is_some());
        assert!(tree.as_mut().append(Node::from_scalar(4u64.into()).into()));
        assert!(tree.as_mut().append(Node::from_scalar(5u64.into()).into()));
        assert!(tree.as_mut().mark().is_some());
        assert!(tree.as_mut().append(Node::from_scalar(6u64.into()).into()));
        assert!(tree.as_mut().append(Node::from_scalar(7u64.into()).into()));
        assert!(tree.as_mut().append(Node::from_scalar(8u64.into()).into()));
        assert!(tree.as_mut().append(Node::from_scalar(9u64.into()).into()));

        let serialized = tree.serialize_to_vec();
        let deserialized = BridgeTree::try_from_slice(&serialized).unwrap();

        assert_eq!(tree, deserialized);
    }
}
