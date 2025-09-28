//! MASP verification wrappers.

mod utilities;

use std::str::FromStr;

use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::Transaction;
use masp_primitives::transaction::components::I128Sum;
use namada_core::address::Address;
use namada_core::chain::BlockHeight;
use namada_core::masp::MaspEpoch;
use namada_core::time::DurationSecs;
use namada_core::token::{Denomination, MaspDigitPos};
use namada_events::extend::ReadFromEventAttributes;
use namada_ibc::{IbcMessage, decode_message, extract_masp_tx_from_envelope};
use namada_io::client::Client;
use namada_token::masp::shielded_wallet::ShieldedQueries;
pub use namada_token::masp::{utils, *};
use namada_tx::event::{MaspEvent, MaspEventKind, MaspTxRef};
use namada_tx::{IndexedTx, Tx};
pub use utilities::{
    IndexerMaspClient, LedgerMaspClient, LinearBackoffSleepMaspClient,
};

use crate::error::{Error, QueryError};
use crate::rpc::{
    query_block, query_conversion, query_denom, query_masp_epoch,
    query_max_block_time_estimate, query_native_token,
};
use crate::{MaybeSend, MaybeSync, token};

/// Extract the relevant shield portions from a [`Tx`] MASP section or an IBC
/// message, if any.
#[allow(clippy::result_large_err)]
fn extract_masp_tx(
    tx: &Tx,
    masp_ref: &MaspTxRef,
) -> Result<Transaction, Error> {
    match masp_ref {
        MaspTxRef::MaspSection(id) => {
            // Simply looking for masp sections attached to the tx
            // is not safe. We don't validate the sections attached to a
            // transaction se we could end up with transactions carrying
            // an unnecessary masp section. We must instead look for the
            // required masp sections published in the events
            Ok(tx
                .get_masp_section(id)
                .ok_or_else(|| {
                    Error::Other(format!(
                        "Missing expected masp transaction with id {id}"
                    ))
                })?
                .clone())
        }
        MaspTxRef::IbcData(hash) => {
            // Dereference the masp ref to the first instance that
            // matches it, even if it is not the exact one that produced
            // the event, the data we extract will be exactly the same
            let masp_ibc_tx = tx
                .commitments()
                .iter()
                .find(|cmt| cmt.data_sechash() == hash)
                .ok_or_else(|| {
                    Error::Other(format!(
                        "Couldn't find data section with hash {hash}"
                    ))
                })?;
            let tx_data = tx.data(masp_ibc_tx).ok_or_else(|| {
                Error::Other("Missing expected data section".to_string())
            })?;

            let IbcMessage::Envelope(envelope) =
                decode_message::<token::Transfer>(&tx_data)
                    .map_err(|e| Error::Other(e.to_string()))?
            else {
                return Err(Error::Other(
                    "Expected IBC packet to be an envelope".to_string(),
                ));
            };

            if let Some(transaction) = extract_masp_tx_from_envelope(&envelope)
            {
                Ok(transaction.masp_tx)
            } else {
                Err(Error::Other(
                    "Failed to retrieve MASP over IBC transaction".to_string(),
                ))
            }
        }
    }
}

// Retrieves all the masp events at the specified height.
async fn get_indexed_masp_events_at_height<C: Client + Sync>(
    client: &C,
    height: BlockHeight,
) -> Result<Vec<MaspEvent>, Error> {
    let maybe_masp_events: Result<Vec<_>, Error> = client
        .block_results(height.0)
        .await
        .map_err(|e| Error::from(QueryError::General(e.to_string())))?
        .end_block_events
        .unwrap_or_default()
        .into_iter()
        .map(|event| {
            // Check if the event is a Masp one
            let Ok(kind) = namada_events::EventType::from_str(&event.kind)
            else {
                return Ok(None);
            };

            let kind = if kind == namada_tx::event::masp_types::TRANSFER {
                MaspEventKind::Transfer
            } else if kind == namada_tx::event::masp_types::FEE_PAYMENT {
                MaspEventKind::FeePayment
            } else {
                return Ok(None);
            };

            // Extract the data from the event's attributes, propagate errors if
            // the masp event does not follow the expected format
            let data =
                MaspTxRef::read_from_event_attributes(&event.attributes)?;
            let tx_index =
                IndexedTx::read_from_event_attributes(&event.attributes)?;

            Ok(Some(MaspEvent {
                tx_index,
                kind,
                data,
            }))
        })
        .collect();

    Ok(maybe_masp_events?.into_iter().flatten().collect())
}

/// An implementation of a shielded wallet
/// along with methods for interacting with a node
#[derive(Default, Debug)]
pub struct ShieldedContext<U: ShieldedUtils>(ShieldedWallet<U>);

impl<U: ShieldedUtils> From<ShieldedContext<U>> for ShieldedWallet<U> {
    fn from(ctx: ShieldedContext<U>) -> Self {
        ctx.0
    }
}
impl<U: ShieldedUtils> ShieldedContext<U> {
    /// Create a new [`ShieldedContext`]
    pub fn new(wallet: ShieldedWallet<U>) -> Self {
        Self(wallet)
    }
}

impl<U: ShieldedUtils> std::ops::Deref for ShieldedContext<U> {
    type Target = ShieldedWallet<U>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<U: ShieldedUtils> std::ops::DerefMut for ShieldedContext<U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

macro_rules! wrap_err {
    ($e:expr) => {
        eyre::WrapErr::wrap_err($e, "Query failed:")
    };
}

impl<U: ShieldedUtils + MaybeSync + MaybeSend> ShieldedQueries<U>
    for ShieldedContext<U>
{
    async fn query_native_token<C: Client + Sync>(
        client: &C,
    ) -> Result<Address, eyre::Report> {
        wrap_err!(query_native_token(client).await)
    }

    async fn query_denom<C: Client + Sync>(
        client: &C,
        token: &Address,
    ) -> Option<Denomination> {
        query_denom(client, token).await
    }

    async fn query_conversion<C: Client + Sync>(
        client: &C,
        asset_type: AssetType,
    ) -> Option<(
        Address,
        Denomination,
        MaspDigitPos,
        MaspEpoch,
        I128Sum,
        MerklePath<Node>,
    )> {
        query_conversion(client, asset_type).await
    }

    async fn query_block<C: Client + Sync>(
        client: &C,
    ) -> Result<Option<u64>, eyre::Report> {
        wrap_err!(query_block(client).await.map(|b| b.map(|h| h.height.0)))
    }

    async fn query_max_block_time_estimate<C: Client + Sync>(
        client: &C,
    ) -> Result<DurationSecs, eyre::Report> {
        wrap_err!(query_max_block_time_estimate(client).await)
    }

    async fn query_masp_epoch<C: Client + Sync>(
        client: &C,
    ) -> Result<MaspEpoch, eyre::Report> {
        wrap_err!(query_masp_epoch(client).await)
    }
}
