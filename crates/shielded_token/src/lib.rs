//! Namada shielded token.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

pub mod conversion;

#[cfg(feature = "masp")]
pub mod masp;
mod storage;
pub mod storage_key;
pub mod utils;
#[cfg(feature = "masp-validation")]
pub mod validation;
#[cfg(feature = "masp-validation")]
pub mod vp;

use std::marker::PhantomData;
use std::str::FromStr;

use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
pub use namada_core::dec::Dec;
pub use namada_core::masp::{MaspEpoch, MaspTransaction, MaspTxId, MaspValue};
use namada_core::masp_primitives::merkle_tree::CommitmentTree;
use namada_core::masp_primitives::sapling::Node as SaplingNode;
pub use namada_state::{
    ConversionLeaf, ConversionState, Error, Key, OptionExt, Result, ResultExt,
    StorageRead, StorageWrite, WithConversionState,
};
use namada_systems::shielded_token as shielded_token_sys;
use serde::{Deserialize, Serialize};
pub use storage::*;

#[cfg(feature = "masp")]
pub use crate::masp::shielded_wallet::ShieldedWallet;

/// Shielded token storage `Read/Write` implementation
#[derive(Debug)]
pub struct ShieldedStore<S>(PhantomData<S>);

impl<S: StorageRead> shielded_token_sys::Read<S> for ShieldedStore<S> {
    fn read_commitment_tree(
        storage: &S,
    ) -> Result<CommitmentTree<SaplingNode>> {
        use crate::storage_key::masp_commitment_tree_key;

        let tree_key = masp_commitment_tree_key();
        let commitment_tree: CommitmentTree<SaplingNode> = storage
            .read(&tree_key)?
            .unwrap_or_else(CommitmentTree::empty);

        Ok(commitment_tree)
    }
}

impl<S: StorageRead + StorageWrite> shielded_token_sys::Write<S>
    for ShieldedStore<S>
{
    fn write_commitment_tree(
        storage: &mut S,
        commitment_tree: CommitmentTree<SaplingNode>,
    ) -> Result<()> {
        use crate::storage_key::masp_commitment_tree_key;

        let tree_key = masp_commitment_tree_key();
        storage.write(&tree_key, commitment_tree)
    }
}

/// Token parameters for each kind of asset held on chain
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Deserialize,
    Serialize,
)]
pub struct ShieldedParams {
    /// Maximum reward rate
    pub max_reward_rate: Dec,
    /// Shielded Pool nominal derivative gain
    pub kd_gain_nom: Dec,
    /// Shielded Pool nominal proportional gain for the given token
    pub kp_gain_nom: Dec,
    /// Target amount for the given token that is locked in the shielded pool
    // TODO(namada#3255): use `Uint` here
    pub locked_amount_target: u64,
}

impl Default for ShieldedParams {
    fn default() -> Self {
        Self {
            max_reward_rate: Dec::from_str("0.1").unwrap(),
            kp_gain_nom: Dec::from_str("0.25").unwrap(),
            kd_gain_nom: Dec::from_str("0.25").unwrap(),
            locked_amount_target: 10_000_u64,
        }
    }
}
