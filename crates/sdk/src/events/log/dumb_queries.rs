//! Silly simple event matcher.

use namada_core::chain::BlockHeight;
use namada_core::collections::HashMap;
use namada_core::hash::Hash;
use namada_core::keccak::KeccakHash;
use namada_ethereum_bridge::event::BridgePoolTxHash;
use namada_ethereum_bridge::event::types::{
    BRIDGE_POOL_EXPIRED, BRIDGE_POOL_RELAYED,
};
use namada_ibc::event::types::UPDATE_CLIENT;
use namada_ibc::event::{
    ClientId as ClientIdAttr, ConsensusHeights, IbcEvent, IbcEventType,
    PacketDstChannel, PacketDstPort, PacketSequence, PacketSrcChannel,
    PacketSrcPort,
};

use crate::events::extend::{
    ExtendAttributesMap, ExtendEventAttributes, TxHash as TxHashAttr,
};
use crate::events::{Event, EventToEmit, EventType, EventTypeBuilder};
use crate::ibc::core::client::types::Height as IbcHeight;
use crate::ibc::core::host::types::identifiers::{
    ChannelId, ClientId, PortId, Sequence,
};
use crate::tx::event::types::APPLIED as APPLIED_TX;

/// A [`QueryMatcher`] verifies if a Namada event matches a
/// given Tendermint query.
#[derive(Debug, Clone)]
pub struct QueryMatcher {
    event_type_match: MatchType,
    event_type: EventType,
    attributes: HashMap<String, String>,
}

/// Determine which kind of match will be performed over a series of event
/// types.
#[derive(Debug, Clone)]
pub enum MatchType {
    /// Exact match.
    Exact,
    /// Prefix match.
    Prefix,
}

impl ExtendAttributesMap for QueryMatcher {
    fn with_attribute<DATA>(&mut self, data: DATA) -> &mut Self
    where
        DATA: ExtendEventAttributes,
    {
        data.extend_event_attributes(&mut self.attributes);
        self
    }
}

impl QueryMatcher {
    /// Returns the event type that this [`QueryMatcher`]
    /// attempts to match.
    pub fn event_type(&self) -> &EventType {
        &self.event_type
    }

    /// Return the match type performed over the
    /// [`EventType`].
    pub fn match_type(&self) -> &MatchType {
        &self.event_type_match
    }

    /// Create a new [`QueryMatcher`] matching event types
    /// with the given `prefix`.
    pub fn of_event_type<E: EventToEmit>() -> Self {
        Self::with_prefix(EventType::new(E::DOMAIN))
    }

    /// Create a new [`QueryMatcher`] matching event types
    /// with the given `prefix`.
    pub fn with_prefix(prefix: EventType) -> Self {
        Self {
            event_type: prefix,
            event_type_match: MatchType::Prefix,
            attributes: Default::default(),
        }
    }

    /// Create a new [`QueryMatcher`] with the given event type.
    pub fn with_event_type(event_type: EventType) -> Self {
        Self {
            event_type,
            event_type_match: MatchType::Exact,
            attributes: Default::default(),
        }
    }

    /// Add a new attribute to the [`QueryMatcher`].
    #[inline]
    pub fn and_attribute<DATA>(mut self, data: DATA) -> Self
    where
        DATA: ExtendEventAttributes,
    {
        self.with_attribute(data);
        self
    }

    /// Checks if this [`QueryMatcher`] validates the
    /// given [`Event`].
    pub fn matches(&self, event: &Event) -> bool {
        let matches_event_type = match self.match_type() {
            MatchType::Exact => *event.kind() == self.event_type,
            MatchType::Prefix => event.kind().starts_with(&*self.event_type),
        };

        if !matches_event_type {
            return false;
        }
        event.has_subset_of_attrs(&self.attributes)
    }

    /// Returns a query matching the given relayed Bridge pool transaction hash.
    pub fn bridge_pool_relayed(tx_hash: &KeccakHash) -> Self {
        Self::with_event_type(BRIDGE_POOL_RELAYED)
            .and_attribute(BridgePoolTxHash(tx_hash))
    }

    /// Returns a query matching the given expired Bridge pool transaction hash.
    pub fn bridge_pool_expired(tx_hash: &KeccakHash) -> Self {
        Self::with_event_type(BRIDGE_POOL_EXPIRED)
            .and_attribute(BridgePoolTxHash(tx_hash))
    }

    /// Returns a query matching the given applied transaction hash.
    pub fn applied(tx_hash: Hash) -> Self {
        Self::with_event_type(APPLIED_TX).and_attribute(TxHashAttr(tx_hash))
    }

    /// Returns a query matching the given IBC UpdateClient parameters
    pub fn ibc_update_client(
        client_id: ClientId,
        consensus_height: BlockHeight,
    ) -> Self {
        Self::with_event_type(UPDATE_CLIENT)
            .and_attribute(ClientIdAttr(client_id))
            .and_attribute(ConsensusHeights(
                IbcHeight::new(0, consensus_height.0).expect("invalid height"),
            ))
    }

    /// Returns a query matching the given IBC packet parameters
    pub fn ibc_packet(
        event_type: IbcEventType,
        source_port: PortId,
        source_channel: ChannelId,
        destination_port: PortId,
        destination_channel: ChannelId,
        sequence: Sequence,
    ) -> Self {
        Self::with_event_type(
            EventTypeBuilder::new_of::<IbcEvent>()
                .with_segment(event_type.0)
                .build(),
        )
        .and_attribute(PacketSrcPort(source_port))
        .and_attribute(PacketSrcChannel(source_channel))
        .and_attribute(PacketDstPort(destination_port))
        .and_attribute(PacketDstChannel(destination_channel))
        .and_attribute(PacketSequence(sequence))
    }

    /// Returns all the events associated with the provided transaction's hash
    pub fn tx_events(tx_hash: Hash) -> Self {
        Self::with_prefix(EventType::new("")).and_attribute(TxHashAttr(tx_hash))
    }
}

#[cfg(test)]
mod tests {
    use namada_ethereum_bridge::event::EthBridgeEvent;
    use namada_token::event::types::TRANSFER;
    use namada_tx::event::masp_types::TRANSFER as MASP_TRANSFER;

    use super::*;
    use crate::events::EventLevel;
    use crate::events::extend::ComposeEvent;

    const HASH: &str =
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";

    /// Test if matching the prefix of an event type works as expected.
    #[test]
    fn test_query_matching_prefix() {
        let matcher = QueryMatcher::of_event_type::<EthBridgeEvent>();

        let tests = {
            let bp_hash: KeccakHash = HASH.parse().unwrap();
            let tx_hash: Hash = HASH.parse().unwrap();

            let event_1: Event =
                Event::new(BRIDGE_POOL_RELAYED, EventLevel::Tx)
                    .with(BridgePoolTxHash(&bp_hash))
                    .into();
            let matches_1 = true;

            let event_2: Event =
                Event::new(BRIDGE_POOL_EXPIRED, EventLevel::Tx)
                    .with(BridgePoolTxHash(&bp_hash))
                    .into();
            let matches_2 = true;

            let event_3: Event = Event::new(UPDATE_CLIENT, EventLevel::Tx)
                .with(TxHashAttr(tx_hash))
                .into();
            let matches_3 = false;

            [
                (event_1, matches_1),
                (event_2, matches_2),
                (event_3, matches_3),
            ]
        };

        for (ev, status) in tests {
            if matcher.matches(&ev) != status {
                panic!("Test failed");
            }
        }
    }

    // Test if we can query all the events associated with a specific
    // transaction's hash
    #[test]
    fn test_query_all_tx_events() {
        let tx_hash: Hash = HASH.parse().unwrap();
        let matcher = QueryMatcher::tx_events(tx_hash);

        let event_1: Event = Event::new(UPDATE_CLIENT, EventLevel::Tx)
            .with(TxHashAttr(tx_hash))
            .into();
        let event_2: Event = Event::new(APPLIED_TX, EventLevel::Tx)
            .with(TxHashAttr(tx_hash))
            .into();
        let event_3: Event = Event::new(TRANSFER, EventLevel::Tx)
            .with(TxHashAttr(tx_hash))
            .into();
        let event_4: Event = Event::new(MASP_TRANSFER, EventLevel::Tx);

        for ev in [event_1, event_2, event_3] {
            assert!(matcher.matches(&ev))
        }
        // Check that the event missing the transaction hash attribute is not
        // captured by the matcher
        assert!(!matcher.matches(&event_4))
    }

    /// Test if query matching is working as expected.
    #[test]
    fn test_tm_query_matching() {
        let tx_hash: Hash = HASH.parse().unwrap();

        let matcher = QueryMatcher::with_event_type(APPLIED_TX)
            .and_attribute(TxHashAttr(tx_hash));

        let tests = {
            let event_1: Event = Event::new(UPDATE_CLIENT, EventLevel::Tx)
                .with(TxHashAttr(tx_hash))
                .into();
            let applied_1 = false;

            let event_2: Event = Event::new(APPLIED_TX, EventLevel::Tx)
                .with(TxHashAttr(tx_hash))
                .into();
            let applied_2 = true;

            [(event_1, applied_1), (event_2, applied_2)]
        };

        for (ev, status) in tests {
            if matcher.matches(&ev) != status {
                panic!("Test failed");
            }
        }
    }
}
