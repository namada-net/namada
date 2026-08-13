//! SDK RPC queries

#![allow(clippy::result_large_err)]

use core::str::FromStr;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use namada_account::Account;
use namada_core::address::{Address, InternalAddress};
use namada_core::arith::checked;
use namada_core::chain::{BlockHeight, Epoch};
use namada_core::collections::{HashMap, HashSet};
use namada_core::dec::{Dec, POS_DECIMAL_PRECISION};
use namada_core::hash::Hash;
use namada_core::ibc::IbcTokenHash;
use namada_core::ibc::apps::transfer::types::PrefixedDenom;
use namada_core::ibc::core::host::types::identifiers::ChannelId;
use namada_core::key::common;
use namada_core::masp::MaspEpoch;
use namada_core::storage::{BlockResults, Key, PrefixValue};
use namada_core::time::DurationSecs;
use namada_core::token::{
    Amount, DenominatedAmount, Denomination, MaspDigitPos,
};
use namada_core::uint::Uint;
use namada_core::{storage, token};
use namada_events::extend::InnerTxHash;
use namada_gas::WholeGas;
use namada_gas::event::GasUsed as GasUsedAttr;
use namada_governance::parameters::GovernanceParameters;
use namada_governance::pgf::parameters::PgfParameters;
use namada_governance::pgf::storage::steward::StewardDetail;
use namada_governance::storage::proposal::{
    StorageProposal, StoredContPGFTarget,
};
use namada_governance::utils::{
    ProposalResult, ProposalVotes, Vote, compute_proposal_result,
};
use namada_ibc::parameters::{IbcParameters, IbcTokenRateLimits};
use namada_ibc::storage::{
    ibc_trace_key, ibc_trace_key_prefix, is_ibc_trace_key, mint_limit_key,
    throughput_limit_key,
};
use namada_ibc::trace::calc_ibc_denom;
use namada_io::{Client, Io, display_line, edisplay_line};
use namada_parameters::{EpochDuration, storage as params_storage};
use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::rewards::PosRewardsRates;
use namada_proof_of_stake::types::{
    BondsAndUnbondsDetails, CommissionPair, LivenessInfo, ValidatorMetaData,
    WeightedValidator,
};
use namada_state::{BlockHeader, LastBlock};
use namada_token::masp::MaspTokenRewardData;
use namada_tx::data::{BatchedTxResult, DryRunResult, ResultCode, TxResult};
use namada_tx::event::{Batch as BatchAttr, Code as CodeAttr};
use serde::{Deserialize, Serialize};

use crate::args::{InputAmount, OsmosisPoolHop, Slippage};
use crate::control_flow::time;
use crate::error::{EncodingError, Error, QueryError, TxSubmitError};
use crate::events::{Event, extend};
use crate::internal_macros::echo_error;
use crate::queries::RPC;
use crate::queries::vp::pos::{
    EnrichedBondsAndUnbondsDetails, ValidatorStateInfo,
};
use crate::tendermint::block::Height;
use crate::tendermint::merkle::proof::ProofOps;
use crate::tendermint_rpc::query::Query;
use crate::{Namada, Tx, error};

/// Query an estimate of the maximum block time.
pub async fn query_max_block_time_estimate<C: Client + Sync>(
    client: &C,
) -> Result<DurationSecs, Error> {
    RPC.shell()
        .max_block_time(client)
        .await
        .map_err(|err| Error::from(QueryError::NoResponse(err.to_string())))
}

/// Identical to [`query_tx_status`], but does not need a [`Namada`]
/// context.
pub async fn query_tx_status2<C, IO>(
    client: &C,
    io: &IO,
    status: TxEventQuery<'_>,
    deadline: time::Instant,
) -> Result<TxAppliedEvents, Error>
where
    C: namada_io::Client + Sync,
    IO: Io + crate::MaybeSend + crate::MaybeSync,
{
    time::Sleep {
        strategy: time::LinearBackoff {
            delta: time::Duration::from_secs(1),
        },
    }
    .timeout(deadline, || async {
        tracing::debug!(query = ?status, "Querying tx status");
        let maybe_event = match query_tx_events(client, status).await {
            Ok(response) => response,
            Err(err) => {
                tracing::debug!(
                    query = ?status,
                    %err,
                    "ABCI query failed, retrying tx status query \
                     after timeout",
                );
                return ControlFlow::Continue(());
            }
        };
        if let Some(e) = maybe_event {
            tracing::debug!(event = ?e, "Found tx event");
            ControlFlow::Break(e)
        } else {
            tracing::debug!(
                query = ?status,
                "No tx events found, retrying tx status query \
                 after timeout",
            );
            ControlFlow::Continue(())
        }
    })
    .await
    .map_err(|_| {
        edisplay_line!(
            io,
            "Transaction status query deadline of {deadline:?} exceeded"
        );
        match status {
            TxEventQuery::Applied(_) => {
                Error::Tx(TxSubmitError::AppliedTimeout)
            }
        }
    })
}

/// Query the status of a given transaction.
///
/// If a response is not delivered until `deadline`, we exit the cli with an
/// error.
pub async fn query_tx_status(
    context: &impl Namada,
    status: TxEventQuery<'_>,
    deadline: time::Instant,
) -> Result<TxAppliedEvents, Error> {
    query_tx_status2(context.client(), context.io(), status, deadline).await
}

/// Query the epoch of the last committed block
pub async fn query_epoch<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<Epoch, error::Error> {
    convert_response::<C, _>(RPC.shell().epoch(client).await)
}

/// Query the epoch of the last committed block
pub async fn query_block_header<C: namada_io::Client + Sync>(
    client: &C,
    height: BlockHeight,
) -> Result<Option<BlockHeader>, error::Error> {
    convert_response::<C, _>(RPC.shell().block_header(client, &height).await)
}

/// Query the masp epoch of the last committed block
pub async fn query_masp_epoch<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<MaspEpoch, error::Error> {
    convert_response::<C, _>(RPC.shell().masp_epoch(client).await)
}

/// Query the address of the native token
pub async fn query_native_token<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<Address, error::Error> {
    convert_response::<C, _>(RPC.shell().native_token(client).await)
}

/// Query the epoch of the given block height, if it exists.
/// Will return none if the input block height is greater than
/// the latest committed block height.
pub async fn query_epoch_at_height<C: namada_io::Client + Sync>(
    client: &C,
    height: BlockHeight,
) -> Result<Option<Epoch>, error::Error> {
    convert_response::<C, _>(RPC.shell().epoch_at_height(client, &height).await)
}

/// Query the last committed block, if any.
pub async fn query_block<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<Option<LastBlock>, error::Error> {
    // NOTE: We're not using `client.latest_block()` because it may return an
    // updated block from pre-commit before it's actually committed
    convert_response::<C, _>(RPC.shell().last_block(client).await)
}

/// A helper to unwrap client's response. Will shut down process on error.
fn unwrap_client_response<C: namada_io::Client, T>(
    response: Result<T, C::Error>,
) -> T {
    response.unwrap_or_else(|err| {
        panic!("Error in the query: {:?}", err.to_string());
    })
}

/// A helper to turn client's response into an error type that can be used with
/// ? The exact error type is a `QueryError::NoResponse`, and thus should be
/// seen as getting no response back from a query.
fn convert_response<C: namada_io::Client, T>(
    response: Result<T, C::Error>,
) -> Result<T, Error> {
    response.map_err(|err| Error::from(QueryError::NoResponse(err.to_string())))
}

/// Query the results of the last committed block
pub async fn query_results<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<Vec<BlockResults>, Error> {
    convert_response::<C, _>(RPC.shell().read_results(client).await)
}

/// Query token amount of owner.
pub async fn get_token_balance<C: namada_io::Client + Sync>(
    client: &C,
    token: &Address,
    owner: &Address,
    height: Option<namada_storage::BlockHeight>,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, _>(
        RPC.vp().token().balance(client, token, owner, height).await,
    )
}

/// Query token total supply.
pub async fn get_token_total_supply<C: namada_io::Client + Sync>(
    client: &C,
    token: &Address,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, _>(RPC.vp().token().total_supply(client, token).await)
}

/// Query the effective total supply of the native token
pub async fn get_effective_native_supply<C: Client + Sync>(
    client: &C,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, _>(
        RPC.vp().token().effective_native_supply(client).await,
    )
}

/// Query the effective total supply of the native token
pub async fn get_staking_rewards_rate<C: Client + Sync>(
    client: &C,
) -> Result<PosRewardsRates, error::Error> {
    convert_response::<C, _>(
        RPC.vp().token().staking_rewards_rate(client).await,
    )
}

/// Check if the given address is a known validator.
pub async fn is_validator<C: namada_io::Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<bool, Error> {
    convert_response::<C, _>(RPC.vp().pos().is_validator(client, address).await)
}

/// Check if the given address is a pgf steward.
pub async fn is_steward<C: namada_io::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    unwrap_client_response::<C, _>(
        RPC.vp().pgf().is_steward(client, address).await,
    )
}

/// Check if a given address is a known delegator
pub async fn is_delegator<C: namada_io::Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<bool, error::Error> {
    convert_response::<C, bool>(
        RPC.vp().pos().is_delegator(client, address, &None).await,
    )
}

/// Check if a given address is a known delegator at the given epoch
pub async fn is_delegator_at<C: namada_io::Client + Sync>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> Result<bool, error::Error> {
    convert_response::<C, bool>(
        RPC.vp()
            .pos()
            .is_delegator(client, address, &Some(epoch))
            .await,
    )
}

/// Find if the given source address has any bonds.
pub async fn has_bonds<C: namada_io::Client + Sync>(
    client: &C,
    source: &Address,
) -> Result<bool, error::Error> {
    convert_response::<C, bool>(RPC.vp().pos().has_bonds(client, source).await)
}

/// Get the set of pgf stewards
pub async fn query_pgf_stewards<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<Vec<StewardDetail>, error::Error> {
    convert_response::<C, Vec<StewardDetail>>(
        RPC.vp().pgf().stewards(client).await,
    )
}

/// Get the set of pgf fundings
pub async fn query_pgf_fundings<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<Vec<StoredContPGFTarget>, error::Error> {
    convert_response::<C, Vec<StoredContPGFTarget>>(
        RPC.vp().pgf().funding(client).await,
    )
}

/// Query the consensus key by validator address
pub async fn query_validator_consensus_keys<C: namada_io::Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<Option<common::PublicKey>, error::Error> {
    convert_response::<C, Option<common::PublicKey>>(
        RPC.vp().pos().consensus_key(client, address).await,
    )
}

/// Get the set of consensus keys registered in the network
pub async fn get_consensus_keys<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<BTreeSet<common::PublicKey>, error::Error> {
    convert_response::<C, BTreeSet<common::PublicKey>>(
        RPC.vp().pos().consensus_key_set(client).await,
    )
}

/// Check if the address exists on chain. Established address exists if it has a
/// stored validity predicate. Implicit and internal addresses always return
/// true.
pub async fn known_address<C: namada_io::Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<bool, Error> {
    match address {
        Address::Established(_) => {
            // Established account exists if it has a VP
            let key = storage::Key::validity_predicate(address);
            query_has_storage_key(client, &key).await
        }
        Address::Implicit(_) | Address::Internal(_) => Ok(true),
    }
}

/// Query a conversion.
pub async fn query_conversion<C: namada_io::Client + Sync>(
    client: &C,
    asset_type: AssetType,
) -> Option<(
    Address,
    Denomination,
    MaspDigitPos,
    MaspEpoch,
    masp_primitives::transaction::components::I128Sum,
    MerklePath<Node>,
)> {
    unwrap_client_response::<C, _>(
        RPC.shell().read_conversion(client, &asset_type).await,
    )
}

/// Query conversions
pub async fn query_conversions<C: namada_io::Client + Sync>(
    client: &C,
    masp_epoch: &MaspEpoch,
) -> Result<
    BTreeMap<
        AssetType,
        (
            Address,
            Denomination,
            MaspDigitPos,
            MaspEpoch,
            masp_primitives::transaction::components::I128Sum,
        ),
    >,
    error::Error,
> {
    convert_response::<C, _>(
        RPC.shell().read_conversions(client, masp_epoch).await,
    )
}

/// Query the total rewards minted by MASP
pub async fn query_masp_total_rewards<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, _>(RPC.vp().token().masp_total_rewards(client).await)
}

/// Query to read the tokens that earn masp rewards.
pub async fn query_masp_reward_tokens<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<Vec<MaspTokenRewardData>, Error> {
    convert_response::<C, _>(RPC.shell().masp_reward_tokens(client).await)
}

/// Query a wasm code hash
pub async fn query_wasm_code_hash(
    context: &impl Namada,
    code_path: impl AsRef<str>,
) -> Result<Hash, error::Error> {
    let hash_key = Key::wasm_hash(code_path.as_ref());
    match query_storage_value_bytes(context.client(), &hash_key, None, false)
        .await?
        .0
    {
        Some(hash) => Ok(Hash::try_from(&hash[..]).expect("Invalid code hash")),
        None => {
            edisplay_line!(
                context.io(),
                "The corresponding wasm code of the code path {} doesn't \
                 exist on chain.",
                code_path.as_ref(),
            );
            Err(Error::from(QueryError::Wasm(
                code_path.as_ref().to_string(),
            )))
        }
    }
}

/// Query a storage value and decode it with [`BorshDeserialize`].
pub async fn query_storage_value<C, T>(
    client: &C,
    key: &storage::Key,
) -> Result<T, Error>
where
    T: BorshDeserialize,
    C: namada_io::Client + Sync,
{
    // In case `T` is a unit (only thing that encodes to 0 bytes), we have to
    // use `storage_has_key` instead of `storage_value`, because `storage_value`
    // returns 0 bytes when the key is not found.
    let maybe_unit = T::try_from_slice(&[]);
    if let Ok(unit) = maybe_unit {
        return if convert_response::<C, _>(
            RPC.shell().storage_has_key(client, key).await,
        )? {
            Ok(unit)
        } else {
            Err(Error::from(QueryError::NoSuchKey(key.to_string())))
        };
    }

    let response = convert_response::<C, _>(
        RPC.shell()
            .storage_value(client, None, None, false, key)
            .await,
    )?;
    if response.data.is_empty() {
        return Err(Error::from(QueryError::NoSuchKey(key.to_string())));
    }
    T::try_from_slice(&response.data[..])
        .map_err(|err| Error::from(EncodingError::Decoding(err.to_string())))
}

/// Query a storage value and the proof without decoding.
pub async fn query_storage_value_bytes<C: namada_io::Client + Sync>(
    client: &C,
    key: &storage::Key,
    height: Option<BlockHeight>,
    prove: bool,
) -> Result<(Option<Vec<u8>>, Option<ProofOps>), error::Error> {
    let data = None;
    let response = convert_response::<C, _>(
        RPC.shell()
            .storage_value(client, data, height, prove, key)
            .await,
    )?;
    Ok(if response.data.is_empty() {
        (None, response.proof)
    } else {
        (Some(response.data), response.proof)
    })
}

/// Query a range of storage values with a matching prefix and decode them with
/// [`BorshDeserialize`]. Returns an iterator of the storage keys paired with
/// their associated values.
pub async fn query_storage_prefix<'a, N: Namada, T>(
    context: &'a N,
    key: &storage::Key,
) -> Result<Option<impl 'a + Iterator<Item = (storage::Key, T)>>, error::Error>
where
    T: BorshDeserialize,
{
    let values = convert_response::<N::Client, _>(
        RPC.shell()
            .storage_prefix(context.client(), None, None, false, key)
            .await,
    )?;
    let decode =
        |PrefixValue { key, value }: PrefixValue| match T::try_from_slice(
            &value[..],
        ) {
            Err(err) => {
                edisplay_line!(
                    context.io(),
                    "Skipping a value for key {}. Error in decoding: {}",
                    key,
                    err
                );
                None
            }
            Ok(value) => Some((key, value)),
        };
    Ok(if values.data.is_empty() {
        None
    } else {
        Some(values.data.into_iter().filter_map(decode))
    })
}

/// Query to check if the given storage key exists.
pub async fn query_has_storage_key<C: namada_io::Client + Sync>(
    client: &C,
    key: &storage::Key,
) -> Result<bool, Error> {
    convert_response::<C, _>(RPC.shell().storage_has_key(client, key).await)
}

/// Represents a query for an event pertaining to the specified transaction
#[derive(Debug, Copy, Clone)]
pub enum TxEventQuery<'a> {
    /// Queries whether transaction with given hash was applied
    Applied(&'a str),
}

impl<'a> TxEventQuery<'a> {
    /// The event type to which this event query pertains
    pub fn event_type(self) -> &'static str {
        match self {
            TxEventQuery::Applied(_) => "applied",
        }
    }

    /// The transaction to which this event query pertains
    pub fn tx_hash(self) -> &'a str {
        match self {
            TxEventQuery::Applied(tx_hash) => tx_hash,
        }
    }
}

/// Transaction event queries are semantically a subset of general queries
impl<'a> From<TxEventQuery<'a>> for Query {
    fn from(tx_query: TxEventQuery<'a>) -> Self {
        match tx_query {
            TxEventQuery::Applied(tx_hash) => {
                Query::default().and_eq("applied.hash", tx_hash)
            }
        }
    }
}

/// Call the corresponding `tx_event_query` RPC method, to fetch
/// the current status of a transaction.
pub async fn query_tx_events<C: namada_io::Client + Sync>(
    client: &C,
    tx_event_query: TxEventQuery<'_>,
) -> std::result::Result<Option<TxAppliedEvents>, <C as namada_io::Client>::Error>
{
    let tx_hash: Hash = tx_event_query.tx_hash().try_into().unwrap();
    match tx_event_query {
        TxEventQuery::Applied(_) => RPC.shell().applied(client, &tx_hash).await,
    }
}

/// Dry run a transaction
pub async fn dry_run_tx<N: Namada>(
    context: &N,
    tx_bytes: Vec<u8>,
) -> Result<DryRunResult, Error> {
    let (data, height, prove) = (Some(tx_bytes), None, false);
    let result = convert_response::<N::Client, _>(
        RPC.shell()
            .dry_run_tx(context.client(), data, height, prove)
            .await,
    )?
    .data;
    let DryRunResult(tx_result, gas_cost) = &result;

    display_line!(context.io(), "Dry-run result:");
    let mut all_inners_successful = true;
    for (inner_hash, cmt_result) in tx_result.iter() {
        match cmt_result {
            Ok(result) => {
                if result.is_accepted() {
                    display_line!(
                        context.io(),
                        "Transaction {inner_hash} was successfully applied",
                    );
                } else {
                    display_line!(
                        context.io(),
                        "Transaction {} was rejected by VPs: {}\nErrors: \
                         {}\nChanged keys: {}",
                        inner_hash,
                        serde_json::to_string_pretty(
                            &result.vps_result.rejected_vps
                        )
                        .unwrap(),
                        serde_json::to_string_pretty(&result.vps_result.errors)
                            .unwrap(),
                        serde_json::to_string_pretty(&result.changed_keys)
                            .unwrap(),
                    );
                    all_inners_successful = false;
                }
            }
            Err(msg) => {
                display_line!(
                    context.io(),
                    "Transaction {inner_hash} failed.\nDetails: {msg}"
                );
                all_inners_successful = false;
            }
        }
    }

    display_line!(
        context.io(),
        "The batch consumed {} gas units.{}",
        gas_cost,
        if all_inners_successful {
            ""
        } else {
            "The gas consumed might be misleading if the inner transactions \
             did not have the chance to run until completion. Do not rely on \
             this value to set gas limit."
        }
    );

    Ok(result)
}

/// Data needed for broadcasting a tx and monitoring its progress on chain.
///
/// Txs may be either a dry run or else they should be included in a wrapper.
#[derive(Debug, Clone)]
pub enum TxBroadcastData {
    /// Dry run broadcast data
    DryRun(Tx),
    /// Live broadcast data
    Live {
        /// Transaction to broadcast
        tx: Tx,
        /// Hash of the transaction
        tx_hash: String,
    },
}

/// The events for an applied transaction
#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct TxAppliedEvents {
    /// The applied tx event
    pub applied: Event,
    /// All the other events associated with this transaction (transfers, ibc,
    /// masp, ...)
    pub other: Vec<Event>,
}

/// A parsed event from tendermint relating to a transaction
#[derive(Debug, Serialize)]
pub struct TxResponse {
    /// Result of the tx batch (wasm), if any
    pub batch: Option<TxResult<String>>,
    /// Response additional information
    pub info: String,
    /// Response log
    pub log: String,
    /// Block height
    pub height: BlockHeight,
    /// Transaction hash
    pub hash: Hash,
    /// Response code
    pub code: ResultCode,
    /// Gas used.
    pub gas_used: WholeGas,
}

/// Determines a result of an inner tx from
/// [`namada_tx::data::BatchedTxResult`].
pub enum InnerTxResult<'a> {
    /// Tx is applied and accepted by all VPs
    Success(&'a BatchedTxResult),
    /// Some VPs rejected the tx
    VpsRejected(&'a BatchedTxResult),
    /// Transaction failed in some other way specified in the associated message
    OtherFailure(String),
}

impl TryFrom<TxAppliedEvents> for TxResponse {
    type Error = String;

    fn try_from(
        TxAppliedEvents {
            applied: applied_event,
            other: other_events,
        }: TxAppliedEvents,
    ) -> Result<Self, Self::Error> {
        let mut batch = applied_event.read_attribute::<BatchAttr<'_>>().ok();
        let hash = applied_event
            .read_attribute::<extend::TxHash>()
            .map_err(|err| err.to_string())?;
        let info = applied_event
            .read_attribute::<extend::Info>()
            .map_err(|err| err.to_string())?;
        let log = applied_event
            .read_attribute::<extend::Log>()
            .map_err(|err| err.to_string())?;
        let height = applied_event
            .read_attribute::<extend::Height>()
            .map_err(|err| err.to_string())?;
        let code = applied_event
            .read_attribute::<CodeAttr>()
            .map_err(|err| err.to_string())?;
        let gas_used = applied_event
            .read_attribute::<GasUsedAttr>()
            .map_err(|err| err.to_string())?;

        // Reconstruct the inner txs' events
        if let Some(batch) = &mut batch {
            for event in other_events {
                let inner_tx_hash = event
                    .read_attribute::<InnerTxHash>()
                    .map_err(|e| e.to_string())?;
                let inner_tx_result =
                    batch.get_mut(&inner_tx_hash).ok_or_else(|| {
                        format!(
                            "Missing result of inner transaction {}",
                            inner_tx_hash
                        )
                    })?;

                if let Ok(result) = inner_tx_result {
                    result.events.insert(event);
                }
            }
        }

        Ok(TxResponse {
            batch,
            info,
            hash,
            log,
            height,
            code,
            gas_used,
        })
    }
}

impl TxResponse {
    /// Convert a [`TxAppliedEvents`] to a [`TxResponse`], or error out.
    pub fn from_events(applied_events: TxAppliedEvents) -> Self {
        applied_events.try_into().unwrap_or_else(|err| {
            panic!("Error fetching TxResponse: {err}");
        })
    }

    /// Check the result of the batch. This should not be used with wrapper
    /// txs.
    pub fn batch_result(&self) -> HashMap<Hash, InnerTxResult<'_>> {
        if let Some(tx_result) = self.batch.as_ref() {
            let mut result = HashMap::default();
            for (inner_hash, cmt_result) in tx_result.iter() {
                let value = match cmt_result {
                    Ok(res) => {
                        if res.is_accepted() {
                            InnerTxResult::Success(res)
                        } else {
                            InnerTxResult::VpsRejected(res)
                        }
                    }
                    Err(msg) => InnerTxResult::OtherFailure(msg.to_owned()),
                };
                result.insert(inner_hash.to_owned(), value);
            }
            result
        } else {
            HashMap::default()
        }
    }
}

/// Get the PoS parameters
pub async fn get_pos_params<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<PosParams, error::Error> {
    convert_response::<C, _>(RPC.vp().pos().pos_params(client).await)
}

/// Get all validators in the given epoch
pub async fn get_all_validators<C: namada_io::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> Result<HashSet<Address>, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .validator_addresses(client, &Some(epoch))
            .await,
    )
}

/// Get liveness info for all consensus validators in the current epoch
pub async fn get_validators_liveness_info<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<LivenessInfo, error::Error> {
    convert_response::<C, _>(RPC.vp().pos().liveness_info(client).await)
}

/// Get all consensus validators in the given epoch
pub async fn get_all_consensus_validators<C: namada_io::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> Result<BTreeSet<WeightedValidator>, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .consensus_validator_set(client, &Some(epoch))
            .await,
    )
}

/// Get the total staked tokens in the given epoch
pub async fn get_total_staked_tokens<C: namada_io::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, _>(
        RPC.vp().pos().total_stake(client, &Some(epoch)).await,
    )
}

/// Get the total active voting power in the given epoch
pub async fn get_total_active_voting_power<C: namada_io::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .total_active_voting_power(client, &Some(epoch))
            .await,
    )
}

/// Get the given validator's stake at the given epoch
pub async fn get_validator_stake<C: namada_io::Client + Sync>(
    client: &C,
    epoch: Epoch,
    validator: &Address,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .validator_stake(client, validator, &Some(epoch))
            .await,
    )
    .map(|t| t.unwrap_or_default())
}

/// Query and return a validator's state
pub async fn get_validator_state<C: namada_io::Client + Sync>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<ValidatorStateInfo, error::Error> {
    convert_response::<C, ValidatorStateInfo>(
        RPC.vp()
            .pos()
            .validator_state(client, validator, &epoch)
            .await,
    )
}

/// Query and return the available reward tokens corresponding to the bond
pub async fn query_rewards<C: namada_io::Client + Sync>(
    client: &C,
    source: &Option<Address>,
    validator: &Address,
    epoch: &Option<Epoch>,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, token::Amount>(
        RPC.vp()
            .pos()
            .rewards(client, validator, source, epoch)
            .await,
    )
}

/// Get the validators to which a delegator is bonded at a certain epoch
pub async fn get_delegation_validators<C: namada_io::Client + Sync>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> Result<HashSet<Address>, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .delegation_validators(client, address, &Some(epoch))
            .await,
    )
}

/// Get the delegations of a delegator at some epoch, including the validator
/// and bond amount
pub async fn get_delegations_of_delegator_at<C: namada_io::Client + Sync>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> Result<HashMap<Address, token::Amount>, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .delegations(client, address, &Some(epoch))
            .await,
    )
}

/// Query proposal by Id
pub async fn query_proposal_by_id<C: namada_io::Client + Sync>(
    client: &C,
    proposal_id: u64,
) -> Result<Option<StorageProposal>, Error> {
    convert_response::<C, _>(
        RPC.vp().gov().proposal_id(client, &proposal_id).await,
    )
}

/// Query and return validator's commission rate and max commission rate change
/// per epoch
pub async fn query_commission_rate<C: namada_io::Client + Sync>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<CommissionPair, Error> {
    convert_response::<C, CommissionPair>(
        RPC.vp()
            .pos()
            .validator_commission(client, validator, &epoch)
            .await,
    )
}

/// Query and return validator's metadata, including the commission rate and max
/// commission rate change
pub async fn query_metadata<C: namada_io::Client + Sync>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<(Option<ValidatorMetaData>, CommissionPair), Error> {
    let metadata = convert_response::<C, Option<ValidatorMetaData>>(
        RPC.vp().pos().validator_metadata(client, validator).await,
    )?;
    let commission_info = convert_response::<C, CommissionPair>(
        RPC.vp()
            .pos()
            .validator_commission(client, validator, &epoch)
            .await,
    )?;
    Ok((metadata, commission_info))
}

/// Query and return the incoming redelegation epoch for a given pair of source
/// validator and delegator, if there is any.
pub async fn query_incoming_redelegations<C: namada_io::Client + Sync>(
    client: &C,
    src_validator: &Address,
    delegator: &Address,
) -> Result<Option<Epoch>, Error> {
    convert_response::<C, Option<Epoch>>(
        RPC.vp()
            .pos()
            .validator_incoming_redelegation(client, src_validator, delegator)
            .await,
    )
}

/// Query a validator's bonds for a given epoch
pub async fn query_bond<C: namada_io::Client + Sync>(
    client: &C,
    source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, token::Amount>(
        RPC.vp().pos().bond(client, source, validator, &epoch).await,
    )
}

/// Query a validator's bonds for a given epoch
pub async fn query_last_infraction_epoch<C: namada_io::Client + Sync>(
    client: &C,
    validator: &Address,
) -> Result<Option<Epoch>, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .validator_last_infraction_epoch(client, validator)
            .await,
    )
}

/// Query the accunt substorage space of an address
pub async fn get_account_info<C: namada_io::Client + Sync>(
    client: &C,
    owner: &Address,
) -> Result<Option<Account>, error::Error> {
    convert_response::<C, Option<Account>>(
        RPC.shell().account(client, owner).await,
    )
}

/// Query if the public_key is revealed
pub async fn is_public_key_revealed<C: namada_io::Client + Sync>(
    client: &C,
    owner: &Address,
) -> Result<bool, error::Error> {
    convert_response::<C, bool>(RPC.shell().revealed(client, owner).await)
}

/// Query an account substorage at a specific index
pub async fn get_public_key_at<C: namada_io::Client + Sync>(
    client: &C,
    owner: &Address,
    index: u8,
) -> Result<Option<common::PublicKey>, Error> {
    let account = convert_response::<C, Option<Account>>(
        RPC.shell().account(client, owner).await,
    )?;
    if let Some(account) = account {
        Ok(account.get_public_key_from_index(index))
    } else {
        Ok(None)
    }
}

/// Query the proposal result
pub async fn query_proposal_result<C: namada_io::Client + Sync>(
    client: &C,
    proposal_id: u64,
) -> Result<Option<ProposalResult>, Error> {
    let proposal = query_proposal_by_id(client, proposal_id).await?;
    let proposal = if let Some(proposal) = proposal {
        proposal
    } else {
        return Ok(None);
    };

    let current_epoch = query_epoch(client).await?;
    if current_epoch < proposal.voting_start_epoch {
        return Ok(None);
    }

    let stored_proposal_result = convert_response::<C, Option<ProposalResult>>(
        RPC.vp().gov().proposal_result(client, &proposal_id).await,
    )?;

    let proposal_result = match stored_proposal_result {
        Some(proposal_result) => proposal_result,
        None => {
            let tally_epoch = current_epoch;

            let is_author_pgf_steward =
                is_steward(client, &proposal.author).await;
            #[allow(clippy::disallowed_methods)]
            let votes = query_proposal_votes(client, proposal_id)
                .await
                .unwrap_or_default();
            let tally_type = proposal.get_tally_type(is_author_pgf_steward);
            #[allow(clippy::disallowed_methods)]
            let total_active_voting_power =
                get_total_active_voting_power(client, tally_epoch)
                    .await
                    .unwrap_or_default();

            let mut proposal_votes = ProposalVotes::default();

            for vote in votes {
                match vote.is_validator() {
                    true => {
                        #[allow(clippy::disallowed_methods)]
                        let voting_power = get_validator_stake(
                            client,
                            tally_epoch,
                            &vote.validator,
                        )
                        .await
                        .unwrap_or_default();

                        proposal_votes.add_validator(
                            &vote.validator,
                            voting_power,
                            vote.data,
                        );
                    }
                    false => {
                        #[allow(clippy::disallowed_methods)]
                        let voting_power = get_bond_amount_at(
                            client,
                            &vote.delegator,
                            &vote.validator,
                            tally_epoch,
                        )
                        .await
                        .unwrap_or_default();

                        proposal_votes.add_delegator(
                            &vote.delegator,
                            &vote.validator,
                            voting_power,
                            vote.data,
                        );
                    }
                }
            }
            compute_proposal_result(
                proposal_votes,
                total_active_voting_power,
                tally_type,
            )?
        }
    };
    Ok(Some(proposal_result))
}

/// Query a validator's unbonds for a given epoch
pub async fn query_and_print_unbonds(
    context: &impl Namada,
    source: &Address,
    validator: &Address,
) -> Result<(), error::Error> {
    let unbonds =
        query_unbond_with_slashing(context.client(), source, validator).await?;
    let current_epoch = query_epoch(context.client()).await?;

    let mut total_withdrawable = token::Amount::zero();
    let mut not_yet_withdrawable = HashMap::<Epoch, token::Amount>::new();
    for ((_start_epoch, withdraw_epoch), amount) in unbonds.into_iter() {
        if withdraw_epoch <= current_epoch {
            checked!(total_withdrawable += amount)?;
        } else {
            let withdrawable_amount =
                not_yet_withdrawable.entry(withdraw_epoch).or_default();
            *withdrawable_amount = checked!(withdrawable_amount + amount)?;
        }
    }
    if !total_withdrawable.is_zero() {
        display_line!(
            context.io(),
            "Total withdrawable now: {}.",
            total_withdrawable.to_string_native()
        );
    }
    if !not_yet_withdrawable.is_empty() {
        display_line!(context.io(), "Current epoch: {current_epoch}.")
    }
    for (withdraw_epoch, amount) in not_yet_withdrawable {
        display_line!(
            context.io(),
            "Amount {} withdrawable starting from epoch {withdraw_epoch}.",
            amount.to_string_native()
        );
    }
    Ok(())
}

/// Query withdrawable tokens in a validator account for a given epoch
pub async fn query_withdrawable_tokens<C: namada_io::Client + Sync>(
    client: &C,
    bond_source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, token::Amount>(
        RPC.vp()
            .pos()
            .withdrawable_tokens(client, bond_source, validator, &epoch)
            .await,
    )
}

/// Query all unbonds for a validator, applying slashes
pub async fn query_unbond_with_slashing<C: namada_io::Client + Sync>(
    client: &C,
    source: &Address,
    validator: &Address,
) -> Result<HashMap<(Epoch, Epoch), token::Amount>, error::Error> {
    convert_response::<C, HashMap<(Epoch, Epoch), token::Amount>>(
        RPC.vp()
            .pos()
            .unbond_with_slashing(client, source, validator)
            .await,
    )
}

/// Get the governance parameters
pub async fn query_governance_parameters<C: namada_io::Client + Sync>(
    client: &C,
) -> GovernanceParameters {
    unwrap_client_response::<C, _>(RPC.vp().gov().parameters(client).await)
}

/// Get the public good fundings parameters
pub async fn query_pgf_parameters<C: namada_io::Client + Sync>(
    client: &C,
) -> PgfParameters {
    unwrap_client_response::<C, _>(RPC.vp().pgf().parameters(client).await)
}

/// Get all the votes of a proposal
pub async fn query_proposal_votes<C: namada_io::Client + Sync>(
    client: &C,
    proposal_id: u64,
) -> Result<Vec<Vote>, error::Error> {
    convert_response::<C, Vec<Vote>>(
        RPC.vp().gov().proposal_id_votes(client, &proposal_id).await,
    )
}

/// Query the information to estimate next epoch start
pub async fn query_next_epoch_info<C: namada_io::Client + Sync>(
    client: &C,
) -> Result<(BlockHeight, EpochDuration), error::Error> {
    let this_epoch_first_height = convert_response::<C, BlockHeight>(
        RPC.shell()
            .first_block_height_of_current_epoch(client)
            .await,
    )?;

    let key = params_storage::get_epoch_duration_storage_key();
    let epoch_duration: EpochDuration =
        query_storage_value(client, &key).await?;

    Ok((this_epoch_first_height, epoch_duration))
}

/// Get the bond amount at the given epoch
pub async fn get_bond_amount_at<C: namada_io::Client + Sync>(
    client: &C,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> Result<token::Amount, error::Error> {
    let total_active = convert_response::<C, Amount>(
        RPC.vp()
            .pos()
            .bond_with_slashing(client, delegator, validator, &Some(epoch))
            .await,
    )?;
    Ok(total_active)
}

/// Get bonds and unbonds with all details (slashes and rewards, if any)
/// grouped by their bond IDs.
pub async fn bonds_and_unbonds<C: namada_io::Client + Sync>(
    client: &C,
    source: &Option<Address>,
    validator: &Option<Address>,
) -> Result<BondsAndUnbondsDetails, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .bonds_and_unbonds(client, source, validator)
            .await,
    )
}

/// Get bonds and unbonds with all details (slashes and rewards, if any)
/// grouped by their bond IDs, enriched with extra information calculated from
/// the data.
pub async fn enriched_bonds_and_unbonds<C: namada_io::Client + Sync>(
    client: &C,
    current_epoch: Epoch,
    source: &Option<Address>,
    validator: &Option<Address>,
) -> Result<EnrichedBondsAndUnbondsDetails, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .enriched_bonds_and_unbonds(
                client,
                current_epoch,
                source,
                validator,
            )
            .await,
    )
}

/// Query the denomination of the given token
pub async fn query_denom<C: namada_io::Client + Sync>(
    client: &C,
    token: &Address,
) -> Option<Denomination> {
    unwrap_client_response::<C, Option<Denomination>>(
        RPC.vp().token().denomination(client, token).await,
    )
}

/// Get the correct representation of the amount given the token type.
pub async fn validate_amount<N: Namada>(
    context: &N,
    amount: InputAmount,
    token: &Address,
    force: bool,
) -> Result<token::DenominatedAmount, Error> {
    let input_amount = match amount {
        InputAmount::Unvalidated(amt) if amt.is_zero() => return Ok(amt),
        InputAmount::Unvalidated(amt) => amt.canonical(),
        InputAmount::Validated(amt) => return Ok(amt),
    };
    let denom = match convert_response::<N::Client, Option<Denomination>>(
        RPC.vp().token().denomination(context.client(), token).await,
    )? {
        Some(denom) => Ok(denom),
        None => {
            if force {
                display_line!(
                    context.io(),
                    "No denomination found for token: {token}, but --force \
                     was passed. Defaulting to the provided denomination."
                );
                Ok(input_amount.denom())
            } else {
                display_line!(
                    context.io(),
                    "No denomination found for token: {token}, the input \
                     arguments could not be parsed."
                );
                Err(Error::from(QueryError::General(format!(
                    "denomination for token {token}"
                ))))
            }
        }
    }?;
    if denom < input_amount.denom() && !force {
        display_line!(
            context.io(),
            "The input amount contained a higher precision than allowed by \
             {token}."
        );
        Err(Error::from(QueryError::General(format!(
            "the input amount. It contained a higher precision than allowed \
             by {token}"
        ))))
    } else {
        input_amount.increase_precision(denom).map_err(|_err| {
            display_line!(
                context.io(),
                "The amount provided requires more the 256 bits to represent."
            );
            Error::from(QueryError::General(
                "the amount provided. It requires more than 256 bits to \
                 represent"
                    .to_string(),
            ))
        })
    }
}

/// Wait for a first block and node to be synced.
pub async fn wait_until_node_is_synched(
    client: &(impl namada_io::Client + Sync),
    io: &impl Io,
) -> Result<(), Error> {
    let height_one = Height::try_from(1_u64).unwrap();
    let try_count = Cell::new(1_u64);
    const MAX_TRIES: usize = 5;

    time::Sleep {
        strategy: time::ExponentialBackoff {
            base: 2,
            as_duration: time::Duration::from_secs,
        },
    }
    .retry(MAX_TRIES, || async {
        let node_status = client.status().await;
        match node_status {
            Ok(status) => {
                let latest_block_height = status.sync_info.latest_block_height;
                let is_catching_up = status.sync_info.catching_up;
                let is_at_least_height_one = latest_block_height >= height_one;
                if is_at_least_height_one && !is_catching_up {
                    return ControlFlow::Break(Ok(()));
                }
                display_line!(
                    io,
                    " Waiting for {} ({}/{} tries)...",
                    if is_at_least_height_one {
                        "a first block"
                    } else {
                        "node to sync"
                    },
                    try_count.get(),
                    MAX_TRIES,
                );
                try_count.set(try_count.get() + 1);
                ControlFlow::Continue(())
            }
            Err(e) => ControlFlow::Break(Err(Error::Query(
                QueryError::General(echo_error!(
                    io,
                    "Failed to query node status with error: {e}"
                )),
            ))),
        }
    })
    .await
    // maybe time out
    .map_err(|_| {
        edisplay_line!(
            io,
            "Node is still catching up, wait for it to finish syncing."
        );
        Error::Query(QueryError::CatchingUp)
    })?
}

/// Look up the denomination of a token in order to make a correctly denominated
/// amount.
pub async fn denominate_amount<C: namada_io::Client + Sync>(
    client: &C,
    io: &impl Io,
    token: &Address,
    amount: token::Amount,
) -> DenominatedAmount {
    let denom = convert_response::<C, Option<Denomination>>(
        RPC.vp().token().denomination(client, token).await,
    )
    .unwrap_or_else(|t| {
        display_line!(io, "Error in querying for denomination: {t}");
        None
    })
    .unwrap_or_else(|| {
        display_line!(
            io,
            "No denomination found for token: {token}, defaulting to zero \
             decimal places"
        );
        0.into()
    });
    DenominatedAmount::new(amount, denom)
}

/// Look up the denomination of a token in order to format it
/// correctly as a string.
pub async fn format_denominated_amount(
    client: &(impl namada_io::Client + Sync),
    io: &impl Io,
    token: &Address,
    amount: token::Amount,
) -> String {
    denominate_amount(client, io, token, amount)
        .await
        .to_string()
}

/// Look up IBC tokens. The given base token can be non-Namada token.
pub async fn query_ibc_tokens<N: Namada>(
    context: &N,
    owner: Option<&Address>,
) -> Result<BTreeMap<String, Address>, Error> {
    let prefix = match owner {
        Some(owner) => ibc_trace_key_prefix(Some(owner.to_string())),
        None => {
            // Check all IBC denoms because the owner might not know IBC token
            // transfers in the same chain
            ibc_trace_key_prefix(None)
        }
    };

    let mut tokens = BTreeMap::new();
    let ibc_traces =
        query_storage_prefix::<_, String>(context, &prefix).await?;
    if let Some(ibc_traces) = ibc_traces {
        for (key, ibc_trace) in ibc_traces {
            if let Some((_, hash)) = is_ibc_trace_key(&key) {
                let hash: IbcTokenHash = hash.parse().expect(
                    "Parsing an IBC token hash from storage shouldn't fail",
                );
                let ibc_token =
                    Address::Internal(InternalAddress::IbcToken(hash));
                tokens.insert(ibc_trace, ibc_token);
            }
        }
    }
    Ok(tokens)
}

/// Look up the IBC denomination from a IbcToken.
pub async fn query_ibc_denom<N: Namada>(
    context: &N,
    token: impl AsRef<str>,
    owner: Option<&Address>,
) -> String {
    let hash = match Address::decode(token.as_ref()) {
        Ok(Address::Internal(InternalAddress::IbcToken(hash))) => {
            hash.to_string()
        }
        _ => return token.as_ref().to_string(),
    };

    if let Some(owner) = owner {
        let ibc_trace_key = ibc_trace_key(owner.to_string(), &hash);
        if let Ok(ibc_denom) =
            query_storage_value::<_, String>(context.client(), &ibc_trace_key)
                .await
        {
            return ibc_denom;
        }
    }

    // No owner is specified or the owner doesn't have the token
    let ibc_denom_prefix = ibc_trace_key_prefix(None);
    if let Ok(Some(ibc_denoms)) =
        query_storage_prefix::<_, String>(context, &ibc_denom_prefix).await
    {
        for (key, ibc_denom) in ibc_denoms {
            if let Some((_, token_hash)) = is_ibc_trace_key(&key) {
                if token_hash == hash {
                    return ibc_denom;
                }
            }
        }
    }

    token.as_ref().to_string()
}

/// Query the registry contract embedded in the state of
/// an input Crosschain Swaps Osmosis contract.
pub async fn get_registry_from_xcs_osmosis_contract(
    lcd_rpc_addr: &str,
    xcs_contract_addr: &str,
) -> Result<String, Error> {
    #[derive(Deserialize)]
    struct RespData {
        models: Vec<Model>,
    }

    #[derive(Deserialize)]
    struct Model {
        key: String,
        value: String,
    }

    #[derive(Deserialize)]
    struct XcsConfig {
        registry_contract: String,
    }

    let request_url = format!(
        "{lcd_rpc_addr}/cosmwasm/wasm/v1/contract/{xcs_contract_addr}/state"
    );
    let RespData { models } = reqwest::get(&request_url)
        .await
        .map_err(|e| {
            Error::Other(format!(
                "Failed to fetch headers of request {request_url:?}: {e}"
            ))
        })?
        .json()
        .await
        .map_err(|e| {
            Error::Other(format!(
                "Failed to fetch JSON body of request {request_url:?}: {e}"
            ))
        })?;

    let Some(Model {
        value: base64_encoded_config,
        ..
    }) = models.into_iter().find(|Model { key, .. }| {
        // NB: this value corresponds to the hex encoding of the
        // string "config". the crosschain swaps contract of the set
        // of xcs contracts stores, in its internal state, the params
        // it was initialized with, namely the address of the registry
        // contract. the point behind querying the initialization
        // params is to ultimately query the address of the registry
        // contract.
        const HEX_ENCODED_CONFIG_KEY: &str = "636F6E666967";
        key == HEX_ENCODED_CONFIG_KEY
    })
    else {
        return Err(Error::Other(format!(
            "Could not find config of XCS contract {xcs_contract_addr}"
        )));
    };

    let xcs_cfg_json = data_encoding::BASE64
        .decode(base64_encoded_config.as_bytes())
        .map_err(|e| Error::Other(e.to_string()))?;

    let XcsConfig { registry_contract } = serde_json::from_slice(&xcs_cfg_json)
        .map_err(|e| Error::Other(e.to_string()))?;

    Ok(registry_contract)
}

/// Given a Namada asset returned from an Osmosis swap,
/// find the corresponding asset denom on Osmosis.
///
/// This is done by querying the XCS registry contract. The Namada asset
/// is also returned, parsed as an [`Address`].
pub async fn osmosis_denom_from_namada_denom(
    lcd_rpc_addr: &str,
    registry_contract_addr: &str,
    namada_denom: &str,
) -> Result<(String, Address), Error> {
    async fn fetch_contract_data(
        contract_addr: &str,
        lcd_rpc_addr: &str,
        json_query: &str,
    ) -> Result<String, Error> {
        #[derive(Deserialize)]
        struct RespData {
            data: String,
        }

        let encoded_query = data_encoding::BASE64.encode(json_query.as_bytes());
        let request_url = format!(
            "{lcd_rpc_addr}/cosmwasm/wasm/v1/contract/{contract_addr}/smart/\
             {encoded_query}"
        );

        let RespData { data } = reqwest::get(&request_url)
            .await
            .map_err(|e| {
                Error::Other(format!(
                    "Failed to fetch headers of request {request_url:?}: {e}"
                ))
            })?
            .json()
            .await
            .map_err(|e| {
                Error::Other(format!(
                    "Failed to fetch JSON body of request {request_url:?}: {e}"
                ))
            })?;

        Ok(data)
    }

    let chain_name_req = |prefix| {
        format!(
            r#"{{"get_chain_name_from_bech32_prefix": {{"prefix": "{prefix}" }} }}"#
        )
    };
    let channel_pair_req = |src, dest| {
        format!(
            r#"{{"get_channel_from_chain_pair": {{"source_chain": "{src}", "destination_chain": "{dest}" }} }}"#
        )
    };
    let dest_chain_req = |on_chain, via_channel| {
        format!(
            r#"{{"get_destination_chain_from_source_chain_via_channel": {{"on_chain": "{on_chain}", "via_channel": "{via_channel}" }} }}"#
        )
    };

    ////////////////////////////////////////////////////////////////////////////

    let nam_denom = PrefixedDenom::from_str(namada_denom).map_err(|e| {
        Error::Other(format!(
            "Could not parse {namada_denom} as a trace path {e}"
        ))
    })?;

    let namada_chain_name = fetch_contract_data(
        registry_contract_addr,
        lcd_rpc_addr,
        &chain_name_req("tnam"),
    )
    .await?;
    let osmosis_chain_name = fetch_contract_data(
        registry_contract_addr,
        lcd_rpc_addr,
        &chain_name_req("osmo"),
    )
    .await?;

    if nam_denom.trace_path.is_empty() {
        // Namada native asset

        let address = nam_denom
            .base_denom
            .as_str()
            .parse::<Address>()
            .map_err(|err| {
                Error::Encode(EncodingError::Decoding(format!(
                    "Failed to parse base denom {} as Namada address: {err}",
                    nam_denom.base_denom
                )))
            })?;

        // validate that the base denom is not another ibc token
        if matches!(&address, Address::Internal(InternalAddress::IbcToken(_))) {
            return Err(Error::Encode(EncodingError::Decoding(format!(
                "Base denom {} cannot be an IBC token hash",
                nam_denom.base_denom
            ))));
        }

        let channel_from_osmosis_to_namada = fetch_contract_data(
            registry_contract_addr,
            lcd_rpc_addr,
            &channel_pair_req(&osmosis_chain_name, &namada_chain_name),
        )
        .await?;

        Ok((
            format!(
                "transfer/{channel_from_osmosis_to_namada}/{}",
                nam_denom.base_denom
            ),
            address,
        ))
    } else {
        let channel_from_namada_to_src: ChannelId = nam_denom
            .trace_path
            .to_string()
            .strip_prefix("transfer/")
            .ok_or_else(|| {
                Error::Other(
                    "Expected the output denom to originate from the transfer \
                     port"
                        .to_string(),
                )
            })?
            .parse()
            .map_err(|_| {
                Error::Other(format!(
                    "Expected a single hop of the form `transfer/channel` in \
                     {namada_denom}"
                ))
            })?;

        // we get chain name from which the base denom originated
        let src_chain_name = fetch_contract_data(
            registry_contract_addr,
            lcd_rpc_addr,
            &dest_chain_req(
                &namada_chain_name,
                channel_from_namada_to_src.as_str(),
            ),
        )
        .await?;

        if src_chain_name == osmosis_chain_name {
            // this is an osmosis native token
            Ok((
                nam_denom.base_denom.to_string(),
                namada_ibc::trace::ibc_token(namada_denom),
            ))
        } else {
            // this asset is not native to osmosis
            let channel_from_osmosis_to_src = fetch_contract_data(
                registry_contract_addr,
                lcd_rpc_addr,
                &channel_pair_req(&osmosis_chain_name, &src_chain_name),
            )
            .await?;

            Ok((
                format!(
                    "transfer/{channel_from_osmosis_to_src}/{}",
                    nam_denom.base_denom
                ),
                namada_ibc::trace::ibc_token(namada_denom),
            ))
        }
    }
}

/// Query the optiomal Osmosis pool route to take, to swap
/// `input_denom` for `output_denom`.
///
/// The minimum and quote price amounts of the trade are also returned.
#[allow(clippy::too_many_arguments)]
pub async fn query_osmosis_route_and_min_out(
    ctx: &impl Namada,
    input_token: &Address,
    input_denom: &str,
    amount: InputAmount,
    output_denom: &str,
    osmosis_sqs_server_url: &str,
    fixed_route: Option<Vec<OsmosisPoolHop>>,
    slippage: Option<Slippage>,
) -> Result<(Vec<OsmosisPoolHop>, Amount, Option<Amount>), Error> {
    let slippage = match (fixed_route, slippage) {
        // fixed routes
        (Some(_), None) => {
            return Err(Error::Other(
                "Slippage must be set manually with fixed routes".to_owned(),
            ));
        }
        (Some(_), Some(Slippage::Twap { .. })) => {
            return Err(Error::Other(
                "TWAP slippage not supported with fixed routes".to_owned(),
            ));
        }
        (Some(route), Some(Slippage::MinOutputAmount(min))) => {
            return Ok((route, min, None));
        }
        // non-fixed routes
        (None, None) => Slippage::Twap {
            // NB: 0.5% slippage by default
            slippage_percentage: Dec::new(5, 1).unwrap(),
        },
        (None, Some(slippage)) => slippage,
    };

    let (mut routes, amount_out_from_routes) = query_osmosis_pool_routes(
        ctx,
        input_token,
        input_denom,
        amount,
        output_denom,
        osmosis_sqs_server_url,
    )
    .await?;

    let route = routes.pop().ok_or_else(|| {
        Error::Other(format!(
            "No route found to swap {amount:?} of {input_denom} with \
             {output_denom}",
        ))
    })?;

    let min_amount_out = match slippage {
        Slippage::MinOutputAmount(min_out)
            if min_out > amount_out_from_routes =>
        {
            return Err(Error::Other(format!(
                "The specified min output amount {min_out} is greater than \
                 the amount {amount_out_from_routes} yielded from the \
                 computed route: {route:?}"
            )));
        }
        Slippage::MinOutputAmount(min_out) => min_out,
        Slippage::Twap {
            slippage_percentage,
        } => {
            // get a value in the range [0, 1]
            let normalized_slippage =
                checked!(slippage_percentage / Dec::new(100, 0).unwrap())?;
            let slippage_complement =
                checked!(Dec::one() - normalized_slippage)?;

            Amount::from_uint(
                amount_out_from_routes
                    .raw_amount()
                    .checked_mul_div(
                        slippage_complement.abs(),
                        Uint::exp10(POS_DECIMAL_PRECISION as _),
                    )
                    .ok_or_else(|| {
                        Error::Other("Failed to compute slippage".to_owned())
                    })?
                    .0,
                0,
            )
            .unwrap()
        }
    };

    if min_amount_out.is_zero() {
        return Err(Error::Other(
            "Forbidding trade with maximum slippage (i.e. 0 as the minimum \
             output amount)"
                .to_owned(),
        ));
    }

    Ok((route, min_amount_out, Some(amount_out_from_routes)))
}

/// Query a route of Osmosis liquidity pools
/// for swapping betwixt token and output_denom
/// assets.
///
/// Also returns the output amount resulting from the
/// trade. Slippage still needs to be subtracted from
/// this output amount.
pub async fn query_osmosis_pool_routes(
    ctx: &impl Namada,
    input_token: &Address,
    input_denom: &str,
    amount: InputAmount,
    output_denom: &str,
    osmosis_sqs_server_url: &str,
) -> Result<(Vec<Vec<OsmosisPoolHop>>, Amount), Error> {
    #[derive(Deserialize)]
    struct PoolHop {
        id: u64,
        token_out_denom: String,
    }

    impl From<PoolHop> for OsmosisPoolHop {
        fn from(value: PoolHop) -> Self {
            Self {
                pool_id: value.id.to_string(),
                token_out_denom: value.token_out_denom,
            }
        }
    }

    #[derive(Deserialize)]
    struct Route {
        pools: Vec<PoolHop>,
    }

    #[derive(Deserialize)]
    struct ResponseOk {
        route: Vec<Route>,
        amount_out: Amount,
    }

    #[derive(Deserialize)]
    struct ResponseErr {
        message: String,
    }

    let coin = {
        let amount = validate_amount(ctx, amount, input_token, false).await?;

        let PrefixedDenom {
            trace_path,
            base_denom,
        } = PrefixedDenom::from_str(input_denom).map_err(|_| {
            Error::Other(format!(
                "Could not decode input {input_denom} as an IBC denom"
            ))
        })?;

        let amount = amount.redenominate(0);

        let token_denom = if trace_path.is_empty() {
            base_denom.to_string()
        } else {
            calc_ibc_denom(input_denom)
        };

        format!("{amount}{token_denom}")
    };
    let output_denom = {
        let PrefixedDenom {
            trace_path,
            base_denom,
        } = PrefixedDenom::from_str(output_denom).map_err(|_| {
            Error::Other(format!(
                "Could not decode output {output_denom} as an IBC denom"
            ))
        })?;

        if trace_path.is_empty() {
            base_denom.to_string()
        } else {
            calc_ibc_denom(output_denom)
        }
    };

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{osmosis_sqs_server_url}/router/quote"))
        .query(&[
            ("tokenIn", coin.as_str()),
            ("tokenOutDenom", output_denom.as_str()),
            ("humanDenoms", "false"),
            ("singleRoute", "true"),
        ])
        .send()
        .await
        .map_err(|err| {
            Error::Other(format!("Failed to query Osmosis SQS: {err}",))
        })?;

    if !response.status().is_success() {
        let ResponseErr { message } = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Failed to read failure response from HTTP request body: {err}"
            ))
        })?;
        return Err(Error::Other(format!(
            "Invalid Osmosis SQS query: {message}"
        )));
    }

    let ResponseOk { route, amount_out } =
        response.json().await.map_err(|err| {
            Error::Other(format!(
                "Failed to read success response from HTTP request body: {err}"
            ))
        })?;

    Ok((
        route
            .into_iter()
            .map(|r| r.pools.into_iter().map(OsmosisPoolHop::from).collect())
            .collect(),
        amount_out,
    ))
}

/// Query the IBC rate limit for the provided token
pub async fn query_ibc_rate_limits<C: Client + Sync>(
    client: &C,
    token: &Address,
) -> Result<IbcTokenRateLimits, error::Error> {
    let throughput_limit =
        query_storage_value::<_, Amount>(client, &throughput_limit_key(token))
            .await
            .ok();
    let mint_limit =
        query_storage_value::<_, Amount>(client, &mint_limit_key(token))
            .await
            .ok();

    Ok(match (mint_limit, throughput_limit) {
        (Some(mint_limit), Some(throughput_per_epoch_limit)) => {
            IbcTokenRateLimits {
                mint_limit,
                throughput_per_epoch_limit,
            }
        }
        _ => {
            let params = query_ibc_params(client).await?;
            IbcTokenRateLimits {
                mint_limit: mint_limit
                    .unwrap_or(params.default_rate_limits.mint_limit),
                throughput_per_epoch_limit: throughput_limit.unwrap_or(
                    params.default_rate_limits.throughput_per_epoch_limit,
                ),
            }
        }
    })
}

/// Query the global IBC parameters
pub async fn query_ibc_params<C: Client + Sync>(
    client: &C,
) -> Result<IbcParameters, error::Error> {
    query_storage_value::<_, IbcParameters>(
        client,
        &namada_ibc::storage::params_key(),
    )
    .await
}
