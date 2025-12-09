//! Shielded token abstract interfaces

use namada_core::address::Address;
use namada_core::masp_primitives::merkle_tree::CommitmentTree;
use namada_core::masp_primitives::sapling::Node;
use namada_core::token;
pub use namada_storage::{Error, Result};

/// Abstract shielded token storage read interface
pub trait Read<S> {
    /// Read the commitment tree from storage.
    fn read_commitment_tree(storage: &S) -> Result<CommitmentTree<Node>>;

    /// Read the undated balance of the given token in the MASP.
    fn read_undated_balance(
        storage: &S,
        token_address: &Address,
    ) -> Result<token::Amount>;
}

/// Abstract shielded token storage write interface
pub trait Write<S>: Read<S> {
    /// Write a commitment tree to storage.
    fn write_commitment_tree(
        storage: &mut S,
        commitment_tree: CommitmentTree<Node>,
    ) -> Result<()>;

    /// Write the undated balance of the given token in the MASP.
    fn write_undated_balance(
        storage: &mut S,
        token_address: &Address,
        balance: token::Amount,
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
