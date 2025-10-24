//! Extend Tendermint votes with Ethereum bridge logic.

pub mod bridge_pool_vext;
pub mod eth_events;
pub mod val_set_update;

use drain_filter_polyfill::DrainFilter;
use namada_sdk::eth_bridge::protocol::transactions::bridge_pool_roots::sign_bridge_pool_root;
use namada_sdk::eth_bridge::protocol::transactions::ethereum_events::sign_ethereum_events;
use namada_sdk::eth_bridge::protocol::transactions::validator_set_update::sign_validator_set_update;
pub use namada_sdk::eth_bridge::protocol::validation::VoteExtensionError;
use namada_sdk::tx::Signed;
use namada_vote_ext::{
    VoteExtension, bridge_pool_roots, ethereum_events, validator_set_update,
};

use super::*;
use crate::shell::abci::TxBytes;

/// Message to be passed to `.expect()` calls in this module.
const VALIDATOR_EXPECT_MSG: &str = "Only validators receive this method call.";

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Creates the data to be added to a vote extension.
    ///
    /// INVARIANT: This method must be stateless.
    #[inline]
    pub fn craft_extension(&mut self) -> VoteExtension {
        VoteExtension {
            ethereum_events: self.extend_vote_with_ethereum_events(),
            bridge_pool_root: self
                .extend_vote_with_bp_roots()
                .map(bridge_pool_roots::SignedVext),
            validator_set_update: self.extend_vote_with_valset_update(),
        }
    }

    /// Extend PreCommit votes with [`ethereum_events::Vext`] instances.
    #[inline]
    pub fn extend_vote_with_ethereum_events(
        &mut self,
    ) -> Option<Signed<ethereum_events::Vext>> {
        let events = self.new_ethereum_events();
        self.sign_ethereum_events(events)
    }

    /// Sign the given Ethereum events, and return the associated
    /// vote extension protocol transaction.
    pub fn sign_ethereum_events(
        &self,
        ethereum_events: Vec<EthereumEvent>,
    ) -> Option<Signed<ethereum_events::Vext>> {
        let validator_addr = self
            .mode
            .get_validator_address()
            .expect(VALIDATOR_EXPECT_MSG);
        let protocol_key = match &self.mode {
            ShellMode::Validator { data, .. } => &data.keys.protocol_keypair,
            _ => unreachable!("{VALIDATOR_EXPECT_MSG}"),
        };
        sign_ethereum_events(
            &self.state,
            validator_addr,
            protocol_key,
            ethereum_events,
        )
        .map(|ethereum_events::SignedVext(ext)| ext)
    }

    /// Extend PreCommit votes with [`bridge_pool_roots::Vext`] instances.
    pub fn extend_vote_with_bp_roots(
        &self,
    ) -> Option<Signed<bridge_pool_roots::Vext>> {
        let validator_addr = self
            .mode
            .get_validator_address()
            .expect(VALIDATOR_EXPECT_MSG);
        let eth_hot_key = self
            .mode
            .get_eth_bridge_keypair()
            .expect(VALIDATOR_EXPECT_MSG);
        let protocol_key = match &self.mode {
            ShellMode::Validator { data, .. } => &data.keys.protocol_keypair,
            _ => unreachable!("{VALIDATOR_EXPECT_MSG}"),
        };
        sign_bridge_pool_root(
            &self.state,
            validator_addr,
            eth_hot_key,
            protocol_key,
        )
        .map(|bridge_pool_roots::SignedVext(ext)| ext)
    }

    /// Extend PreCommit votes with [`validator_set_update::Vext`]
    /// instances.
    pub fn extend_vote_with_valset_update(
        &self,
    ) -> Option<validator_set_update::SignedVext> {
        let validator_addr = self
            .mode
            .get_validator_address()
            .expect(VALIDATOR_EXPECT_MSG);
        let eth_hot_key = self
            .mode
            .get_eth_bridge_keypair()
            .expect("{VALIDATOR_EXPECT_MSG}");
        sign_validator_set_update::<_, _, governance::Store<_>>(
            &self.state,
            validator_addr,
            eth_hot_key,
        )
    }

    /// Given a slice of [`TxBytes`], return an iterator over the
    /// ones we could deserialize to vote extension protocol txs.
    pub fn deserialize_vote_extensions<'shell>(
        &'shell self,
        txs: &'shell mut Vec<TxBytes>,
    ) -> DrainFilter<'shell, TxBytes, impl FnMut(&mut TxBytes) -> bool + 'shell>
    {
        drain_filter_polyfill::VecExt::drain_filter(txs, move |tx_bytes| {
            let tx = match Tx::try_from_bytes(tx_bytes.as_ref()) {
                Ok(tx) => tx,
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        "Failed to deserialize tx in \
                         deserialize_vote_extensions"
                    );
                    return false;
                }
            };
            match (&tx).try_into().ok() {
                Some(EthereumTxData::BridgePoolVext(_)) => true,
                Some(EthereumTxData::EthEventsVext(ext)) => {
                    // NB: only propose events with at least
                    // one valid nonce
                    ext.data.ethereum_events.iter().any(|event| {
                        self.state
                            .ethbridge_queries()
                            .validate_eth_event_nonce(event)
                    })
                }
                Some(EthereumTxData::ValSetUpdateVext(ext)) => {
                    // only include non-stale validator set updates
                    // in block proposals. it might be sitting long
                    // enough in the mempool for it to no longer be
                    // relevant to propose (e.g. a proof was constructed
                    // before this validator set update got a chance
                    // to be decided). unfortunately, we won't be able
                    // to remove it from the mempool this way, but it
                    // will eventually be evicted, getting replaced
                    // by newer txs.
                    let is_seen = self
                        .state
                        .ethbridge_queries()
                        .valset_upd_seen(ext.data.signing_epoch.next());
                    !is_seen
                }
                _ => false,
            }
        })
    }
}

/// Yields an iterator over the protocol transactions
/// in a [`VoteExtension`].
pub fn iter_protocol_txs(
    ext: VoteExtension,
) -> impl Iterator<Item = EthereumTxData> {
    let VoteExtension {
        ethereum_events,
        bridge_pool_root,
        validator_set_update,
    } = ext;
    [
        ethereum_events.map(|e| {
            EthereumTxData::EthEventsVext(ethereum_events::SignedVext(e))
        }),
        bridge_pool_root.map(EthereumTxData::BridgePoolVext),
        validator_set_update.map(EthereumTxData::ValSetUpdateVext),
    ]
    .into_iter()
    .flatten()
}
