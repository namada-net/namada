//! MASP utilities

use std::collections::BTreeSet;

use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::Transaction;
use namada_core::masp::MaspTxData;

use crate::storage_key::{
    is_masp_transfer_key, masp_commitment_tree_key, masp_nullifier_key,
};
use crate::{Error, Key, Result, StorageRead, StorageWrite};

// Writes the nullifiers of the provided masp transaction to storage
fn reveal_nullifiers(
    ctx: &mut impl StorageWrite,
    transaction: &impl MaspTxData,
) -> Result<()> {
    for nullifier in transaction.nullifiers() {
        ctx.write(&masp_nullifier_key(&nullifier), ())?;
    }

    Ok(())
}

/// Appends the note commitments of the provided transaction to the merkle tree
/// and updates the anchor.
///
/// NOTE: this function is public as a temporary workaround because of an issue
/// when running it in WASM (<https://github.com/anoma/masp/issues/73>)
pub fn update_note_commitment_tree(
    ctx: &mut (impl StorageRead + StorageWrite),
    transaction: &impl MaspTxData,
) -> Result<()> {
    if let Some(nodes) = transaction.note_commitments() {
        let tree_key = masp_commitment_tree_key();
        let mut commitment_tree: CommitmentTree<Node> =
            ctx.read(&tree_key)?.ok_or(Error::SimpleMessage(
                "Missing note commitment tree in storage",
            ))?;

        for node in nodes {
            // Add cmu to the merkle tree
            commitment_tree.append(node).map_err(|_| {
                Error::SimpleMessage("Note commitment tree is full")
            })?;
        }
        ctx.write(&tree_key, commitment_tree)?;
    }

    Ok(())
}

/// Handle a MASP transaction.
pub fn handle_masp_tx(
    ctx: &mut (impl StorageRead + StorageWrite),
    shielded: &Transaction,
) -> Result<()> {
    // TODO(masp#73): temporarily disabled because of the node aggregation issue
    // in WASM. Using the host env tx_update_masp_note_commitment_tree or
    // directly the update_note_commitment_tree function as a  workaround
    // instead update_note_commitment_tree(ctx, shielded)?;
    reveal_nullifiers(ctx, shielded)?;

    Ok(())
}

/// Check if a transaction is a MASP transfer transaction.
///
/// We do that by looking at the changed keys. We cannot simply check that the
/// MASP VP was triggered, as this can be manually requested to be triggered by
/// users.
pub fn is_masp_transfer(changed_keys: &BTreeSet<Key>) -> bool {
    changed_keys.iter().any(is_masp_transfer_key)
}
