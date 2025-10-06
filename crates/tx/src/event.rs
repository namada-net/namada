//! Transaction events.

use std::fmt::Display;
use std::str::FromStr;

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::hash::Hash;
use namada_core::ibc::IbcTxDataHash;
use namada_core::masp::MaspTxId;
use namada_events::extend::{
    ComposeEvent, EventAttributeEntry, Height, Log, TxHash,
};
use namada_events::{Event, EventLevel, EventToEmit, EventType};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

use super::Tx;
use crate::data::{ResultCode, TxResult};
use crate::{IndexedTx, TxType};

/// Transaction event.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct TxEvent(pub Event);

impl From<TxEvent> for Event {
    #[inline]
    fn from(TxEvent(event): TxEvent) -> Self {
        event
    }
}

impl EventToEmit for TxEvent {
    const DOMAIN: &'static str = "tx";
}

pub mod types {
    //! Transaction event types.

    use namada_events::EventType;

    use super::TxEvent;

    /// Applied transaction.
    pub const APPLIED: EventType =
        namada_events::event_type!(TxEvent, "applied");
}

/// Creates a new event with the hash and height of the transaction
/// already filled in.
pub fn new_tx_event(tx: &Tx, height: u64) -> Event {
    let base_event = match tx.header().tx_type {
        TxType::Wrapper(_) | TxType::Protocol(_) => {
            Event::new(types::APPLIED, EventLevel::Tx)
                .with(TxHash(tx.header_hash()))
        }
        _ => unreachable!(),
    };
    let comet_tx_hash = tx.comet_tx_hash();
    base_event
        .with(Height(height.into()))
        .with(Log(String::new()))
        .with(CometTxHash(comet_tx_hash))
        .into()
}

/// Extend an [`Event`] with result code data.
pub struct Code(pub ResultCode);

impl EventAttributeEntry<'static> for Code {
    type Value = ResultCode;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "code";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with batch data.
pub struct Batch<'result>(pub &'result TxResult<String>);

impl<'result> EventAttributeEntry<'result> for Batch<'result> {
    type Value = &'result TxResult<String>;
    type ValueOwned = TxResult<String>;

    const KEY: &'static str = "batch";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

pub mod masp_types {
    //! MASP event types

    use namada_events::EventType;

    use super::MaspEvent;

    /// MASP fee payment event
    pub const FEE_PAYMENT: EventType =
        namada_events::event_type!(MaspEvent, "fee-payment");

    /// General MASP transfer event
    pub const TRANSFER: EventType =
        namada_events::event_type!(MaspEvent, "transfer");
}

/// MASP event kind
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    PartialOrd,
    PartialEq,
    Eq,
    Ord,
    Serialize,
    Deserialize,
    Hash,
)]
pub enum MaspEventKind {
    /// A MASP transaction used for fee payment
    FeePayment,
    /// A general MASP transfer
    #[default]
    Transfer,
}

impl From<&MaspEventKind> for EventType {
    fn from(masp_event_kind: &MaspEventKind) -> Self {
        match masp_event_kind {
            MaspEventKind::FeePayment => masp_types::FEE_PAYMENT,
            MaspEventKind::Transfer => masp_types::TRANSFER,
        }
    }
}

impl From<MaspEventKind> for EventType {
    fn from(masp_event_kind: MaspEventKind) -> Self {
        (&masp_event_kind).into()
    }
}

/// A type representing the possible reference to some MASP data, either a masp
/// section or ibc tx data
#[derive(Clone, Serialize, Deserialize)]
pub enum MaspTxRef {
    /// Reference to a MASP section
    MaspSection(MaspTxId),
    /// Reference to an ibc tx data section
    IbcData(IbcTxDataHash),
}

impl Display for MaspTxRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl FromStr for MaspTxRef {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

/// A list of MASP tx references
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct MaspTxRefs(pub Vec<(IndexedTx, MaspTxRef)>);

/// MASP transaction event
pub struct MaspEvent {
    /// The indexed transaction that generated this event
    pub tx_index: IndexedTx,
    /// A flag signaling the type of the masp transaction
    pub kind: MaspEventKind,
    /// The reference to the masp data
    pub data: MaspTxRef,
}

impl EventToEmit for MaspEvent {
    const DOMAIN: &'static str = "masp";
}

impl From<MaspEvent> for Event {
    fn from(masp_event: MaspEvent) -> Self {
        Self::new(masp_event.kind.into(), EventLevel::Tx)
            .with(masp_event.data)
            .with(masp_event.tx_index)
            .into()
    }
}

impl EventAttributeEntry<'static> for MaspTxRef {
    type Value = MaspTxRef;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "section";

    fn into_value(self) -> Self::Value {
        self
    }
}

impl EventAttributeEntry<'static> for IndexedTx {
    type Value = IndexedTx;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "indexed-tx";

    fn into_value(self) -> Self::Value {
        self
    }
}

/// Extend an [`Event`] with CometBFT tx hash.
pub struct CometTxHash(pub Hash);

impl EventAttributeEntry<'static> for CometTxHash {
    type Value = Hash;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "comet-tx-hash";

    fn into_value(self) -> Self::Value {
        self.0
    }
}
