//! Consensus version compatibility.
//!
//! The block proposer injects a small non-executable protocol tx, the
//! consensus version marker, at the front of every proposal. The marker
//! carries the proposer's consensus version (`namada_core::
//! consensus_version()`), compared verbatim by every node in
//! `ProcessProposal`, before any tx is executed. Proposals carrying a
//! marker with an incompatible version — or with no marker at all —
//! are rejected, preventing state divergence between versions.

use namada_sdk::borsh::BorshSerializeExt;
use namada_sdk::chain::ChainId;
use namada_sdk::key::common;
use namada_sdk::tx::data::protocol::{ProtocolTx, ProtocolTxType};
use namada_sdk::tx::data::TxType;
use namada_sdk::tx::{Data, Tx};
use namada_vote_ext::{ConsensusVersion, protocol_tx_data_variants};

/// Space, in bytes, reserved at the front of every proposal for the
/// consensus version marker tx. The marker is much smaller than this;
/// the reserve simply bounds the accounting overhead.
pub const VERSION_MARKER_RESERVED_SPACE: u64 = 1024;

/// Check if a consensus version carried by a consensus version marker
/// is compatible with `own_version`. Versions are compared verbatim:
/// patch releases and dirty builds of the same consensus version are
/// compatible by construction.
#[inline]
pub fn is_version_compatible(
    own_version: u64,
    marker_version: &ConsensusVersion,
) -> bool {
    marker_version.0 == own_version
}

/// Craft the unsigned consensus version marker protocol tx carrying
/// `version`. The marker is only ever injected directly into a proposal
/// by the block proposer and never broadcast to the mempool, so it
/// carries no signature.
pub fn build_version_marker_tx(version: u64, chain_id: ChainId) -> Tx {
    let mut tx = Tx::from_type(TxType::Protocol(Box::new(ProtocolTx {
        pk: dummy_pk(),
        tx: ProtocolTxType::ConsensusVersionMarker,
    })));
    tx.header.chain_id = chain_id;
    tx.set_data(Data::new(
        ConsensusVersion(version).serialize_to_vec(),
    ));
    tx
}

/// Extract the consensus version from a consensus version marker tx.
/// Returns `None` if the tx is not a consensus version marker or its
/// data cannot be deserialized.
pub fn extract_marker_version(tx: &Tx) -> Option<ConsensusVersion> {
    let TxType::Protocol(protocol_tx) = &tx.header().tx_type else {
        return None;
    };
    if !matches!(
        protocol_tx.tx,
        ProtocolTxType::ConsensusVersionMarker
    ) {
        return None;
    }
    protocol_tx_data_variants::ConsensusVersionMarker::try_from(tx).ok()
}

/// A placeholder public key for the unsigned marker tx. Never verified.
fn dummy_pk() -> common::PublicKey {
    common::PublicKey::Ed25519(namada_sdk::key::ed25519::PublicKey::dummy())
}
