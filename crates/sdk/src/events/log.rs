//! A log to store events emitted by `FinalizeBlock` calls in the ledger.
//!
//! The log will hold up to `N` events of a certain kind at a time, before
//! resorting to pruning older events contained within.

use circular_queue::CircularQueue;
use patricia_tree::map::StringPatriciaMap;

use super::{EmitEvents, Event, EventType};

pub mod dumb_queries;

/// Parameters to configure the pruning of the event log.
#[derive(Debug, Copy, Clone)]
pub struct Params {
    /// Soft limit on the maximum number of events the event log can hold,
    /// for a given event kind.
    ///
    /// If the number of events of a given type in the log exceeds this value,
    /// events of that kind in the log will be pruned.
    pub max_log_events_per_kind: usize,
}

impl Default for Params {
    fn default() -> Self {
        // TODO(namada#3237): tune the default params
        Self {
            max_log_events_per_kind: 50000,
        }
    }
}

/// Represents a log of [`Event`] instances emitted by
/// `FinalizeBlock` calls, in the ledger.
#[derive(Debug)]
pub struct EventLog {
    cap: usize,
    map: StringPatriciaMap<CircularQueue<Event>>,
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl EmitEvents for EventLog {
    #[inline]
    fn emit<E>(&mut self, event: E)
    where
        E: Into<Event>,
    {
        self.log_events(core::iter::once(event.into()));
    }

    /// Emit a batch of [events](Event).
    #[inline]
    fn emit_many<B, E>(&mut self, event_batch: B)
    where
        B: IntoIterator<Item = E>,
        E: Into<Event>,
    {
        self.log_events(event_batch.into_iter().map(Into::into));
    }
}

impl EventLog {
    /// Retrieve an event queue of a given type.
    fn get_queue_of_type(
        &mut self,
        event_type: &EventType,
    ) -> &mut CircularQueue<Event> {
        let event_type = event_type.to_string();

        if namada_core::hints::unlikely(!self.map.contains_key(&event_type)) {
            // some monkey business
            self.map
                .insert(&event_type, CircularQueue::with_capacity(self.cap));
        }

        self.map.get_mut(&event_type).unwrap()
    }

    /// Return a new event log.
    pub fn new(params: Params) -> Self {
        Self {
            cap: params.max_log_events_per_kind,
            map: StringPatriciaMap::new(),
        }
    }

    /// Log a new batch of events into the event log.
    pub fn log_events<E>(&mut self, events: E)
    where
        E: IntoIterator<Item = Event>,
    {
        let mut num_entries = 0;
        for event in events.into_iter() {
            self.get_queue_of_type(event.kind()).push(event);
            num_entries += 1;
        }
        tracing::debug!(num_entries, "Added new entries to the event log");
    }

    /// Returns a new iterator over this [`EventLog`].
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Event> {
        self.map.values().flat_map(|queue| queue.iter())
    }

    /// Returns an adapter that turns this [`EventLog`] into
    /// a filtering iterator over the events contained within.
    #[inline]
    pub fn with_matcher(
        &self,
        matcher: dumb_queries::QueryMatcher,
    ) -> WithMatcher<'_> {
        WithMatcher { matcher, log: self }
    }
}

/// Iterator over an [`EventLog`] taking a [matcher](dumb_queries::QueryMatcher)
/// in order to filter events within.
pub struct WithMatcher<'log> {
    log: &'log EventLog,
    matcher: dumb_queries::QueryMatcher,
}

impl<'log> WithMatcher<'log> {
    /// Iterates and filters events in the associated [`EventLog`]
    /// using the provided [event matcher](dumb_queries::QueryMatcher).
    pub fn iter<'this: 'log>(
        &'this self,
    ) -> impl Iterator<Item = &'log Event> + 'log {
        self.log
            .map
            .iter_prefix(self.matcher.event_type())
            .flat_map(|(_, queue)| {
                queue.iter().filter(|&event| self.matcher.matches(event))
            })
    }
}

#[cfg(test)]
mod event_log_tests {
    use namada_core::hash::Hash;

    use super::*;
    use crate::events::EventLevel;
    use crate::events::extend::{ComposeEvent, TxHash};
    use crate::tx::event::types::APPLIED as APPLIED_TX;

    const HASH: &str =
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";

    /// An applied tx hash query.
    macro_rules! applied {
        ($hash:expr) => {
            dumb_queries::QueryMatcher::applied(Hash::try_from($hash).unwrap())
        };
    }

    /// Return a mock `FinalizeBlock` event.
    fn mock_event(event_type: EventType, hash: impl AsRef<str>) -> Event {
        Event::new(event_type, EventLevel::Tx)
            .with(TxHash(Hash::try_from(hash.as_ref()).unwrap()))
            .into()
    }

    /// Return a vector of mock `FinalizeBlock` events.
    fn mock_tx_events(hash: &str) -> Vec<Event> {
        vec![mock_event(APPLIED_TX, hash)]
    }

    /// Test adding a couple of events to the event log, and
    /// reading those events back.
    #[test]
    fn test_log_add() {
        const NUM_HEIGHTS: usize = 4;

        let mut log = EventLog::new(Params::default());

        // add new events to the log
        let events = mock_tx_events(HASH);

        for _ in 0..NUM_HEIGHTS {
            log.log_events(events.clone());
        }

        // inspect log
        assert_eq!(log.iter().count(), NUM_HEIGHTS * events.len());

        let events_in_log: Vec<_> =
            log.with_matcher(applied!(HASH)).iter().cloned().collect();

        assert_eq!(events_in_log.len(), NUM_HEIGHTS);

        for event in events_in_log {
            assert_eq!(events[0], event);
        }
    }

    /// Test pruning old events from the log.
    #[test]
    fn test_log_prune() {
        const LOG_CAP: usize = 4;

        if LOG_CAP == 0 {
            panic!();
        }

        let mut log = EventLog::new(Params {
            max_log_events_per_kind: LOG_CAP,
        });

        // completely fill the log with events
        for i in 0..LOG_CAP {
            log.emit(mock_event(APPLIED_TX, format!("{i:064X}")));
        }

        // inspect log - it should be full
        let events_in_log: Vec<_> = log.iter().cloned().collect();

        assert_eq!(events_in_log.len(), LOG_CAP);

        // iter in reverse since the ringbuf gives us items
        // in the order of the last insertion
        for (i, event) in events_in_log.into_iter().rev().enumerate() {
            assert_eq!(mock_event(APPLIED_TX, format!("{i:064X}")), event);
        }

        // add a new APPLIED event to the log
        log.emit(mock_event(APPLIED_TX, HASH));

        // inspect log - oldest event should have been pruned
        let events_in_log: Vec<_> = log.iter().cloned().collect();

        assert_eq!(events_in_log.len(), LOG_CAP);
        assert_eq!(events_in_log[0], mock_event(APPLIED_TX, HASH));

        for (i, event) in events_in_log
            .into_iter()
            .rev()
            .enumerate()
            .take(LOG_CAP - 1)
        {
            let i = i + 1; // last elem was pruned
            assert_eq!(mock_event(APPLIED_TX, format!("{i:064X}")), event);
        }
    }
}
