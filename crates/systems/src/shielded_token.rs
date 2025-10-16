//! Shielded token abstract interfaces

use namada_core::masp_primitives::merkle_tree::CommitmentTree;
use namada_core::masp_primitives::sapling::Node;
pub use namada_storage::{Error, Result};

/// Abstract shielded token storage read interface
pub trait Read<S> {
    /// Read the commitment tree from storage.
    fn read_commitment_tree(storage: &S) -> Result<CommitmentTree<Node>>;
}

/// Abstract shielded token storage write interface
pub trait Write<S>: Read<S> {
    /// Write a commitment tree to storage.
    fn write_commitment_tree(
        storage: &mut S,
        commitment_tree: CommitmentTree<Node>,
    ) -> Result<()>;

    /// Update the commitment tree in storage.
    fn update_commitment_tree<I>(storage: &mut S, commitments: I) -> Result<()>
    where
        I: IntoIterator<Item = Node>,
    {
        let mut commitment_tree = Self::read_commitment_tree(storage)?;

        for cmu in commitments {
            // Add cmu to the merkle tree
            commitment_tree.append(cmu).map_err(|_| {
                Error::SimpleMessage("Note commitment tree is full")
            })?;
        }

        Self::write_commitment_tree(storage, commitment_tree)
    }
}
