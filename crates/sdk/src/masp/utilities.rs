//! Helper functions and types

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, RwLock};

use borsh::BorshDeserialize;
use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::Node;
use masp_primitives::transaction::Transaction as MaspTx;
use namada_core::chain::BlockHeight;
use namada_core::collections::HashMap;
use namada_core::control_flow::time::{
    Duration, LinearBackoff, Sleep, SleepStrategy,
};
use namada_core::storage::TxIndex;
use namada_io::Client;
use namada_token::masp::utils::{
    IndexedNoteEntry, MaspClient, MaspClientCapabilities, MaspIndexedTx,
    MaspTxKind,
};
use namada_tx::event::MaspEvent;
use namada_tx::{IndexedTx, Tx};
use tokio::sync::{OnceCell, Semaphore};

use crate::error::{Error, QueryError};
use crate::masp::{extract_masp_tx, get_indexed_masp_events_at_height};

/// Middleware MASP client implementation that introduces
/// linear backoff sleeps between failed requests.
pub struct LinearBackoffSleepMaspClient<M> {
    middleware_client: M,
    shared: Arc<LinearBackoffSleepMaspClientShared>,
}

struct LinearBackoffSleepMaspClientShared {
    backoff: RwLock<Duration>,
    sleep: Sleep<LinearBackoff>,
}

impl<M> LinearBackoffSleepMaspClient<M> {
    /// Create a new [`MaspClient`] with linear backoff
    /// sleep between failed requests.
    #[inline(always)]
    pub fn new(middleware_client: M, linear_backoff_delta: Duration) -> Self {
        Self {
            middleware_client,
            shared: Arc::new(LinearBackoffSleepMaspClientShared {
                backoff: RwLock::new(Duration::from_secs(0)),
                sleep: Sleep {
                    strategy: LinearBackoff {
                        delta: linear_backoff_delta,
                    },
                },
            }),
        }
    }
}

impl<M: Clone> Clone for LinearBackoffSleepMaspClient<M> {
    fn clone(&self) -> Self {
        Self {
            middleware_client: self.middleware_client.clone(),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<M: MaspClient> MaspClient for LinearBackoffSleepMaspClient<M> {
    type Error = <M as MaspClient>::Error;

    async fn last_block_height(
        &self,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        with_linear_backoff(
            &self.shared.backoff,
            &self.shared.sleep,
            self.middleware_client.last_block_height(),
        )
        .await
    }

    async fn fetch_shielded_transfers(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Self::Error> {
        with_linear_backoff(
            &self.shared.backoff,
            &self.shared.sleep,
            self.middleware_client.fetch_shielded_transfers(from, to),
        )
        .await
    }

    fn capabilities(&self) -> MaspClientCapabilities {
        self.middleware_client.capabilities()
    }

    async fn fetch_commitment_tree(
        &self,
        height: BlockHeight,
    ) -> Result<CommitmentTree<Node>, Self::Error> {
        with_linear_backoff(
            &self.shared.backoff,
            &self.shared.sleep,
            self.middleware_client.fetch_commitment_tree(height),
        )
        .await
    }

    async fn fetch_note_index(
        &self,
        height: BlockHeight,
    ) -> Result<BTreeMap<MaspIndexedTx, usize>, Self::Error> {
        with_linear_backoff(
            &self.shared.backoff,
            &self.shared.sleep,
            self.middleware_client.fetch_note_index(height),
        )
        .await
    }

    async fn fetch_witness_map(
        &self,
        height: BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Self::Error> {
        with_linear_backoff(
            &self.shared.backoff,
            &self.shared.sleep,
            self.middleware_client.fetch_witness_map(height),
        )
        .await
    }

    async fn commitment_anchor_exists(
        &self,
        root: &Node,
    ) -> Result<bool, Self::Error> {
        with_linear_backoff(
            &self.shared.backoff,
            &self.shared.sleep,
            self.middleware_client.commitment_anchor_exists(root),
        )
        .await
    }
}

struct LedgerMaspClientInner<C> {
    client: C,
    semaphore: Semaphore,
}

/// An inefficient MASP client which simply uses a
/// client to the blockchain to query it
pub struct LedgerMaspClient<C> {
    inner: Arc<LedgerMaspClientInner<C>>,
}

impl<C> Clone for LedgerMaspClient<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<C> LedgerMaspClient<C> {
    /// Create a new [`MaspClient`] given an rpc client.
    #[inline(always)]
    pub fn new(client: C, max_concurrent_fetches: usize) -> Self {
        Self {
            inner: Arc::new(LedgerMaspClientInner {
                client,
                semaphore: Semaphore::new(max_concurrent_fetches),
            }),
        }
    }
}

impl<C: Client + Send + Sync> MaspClient for LedgerMaspClient<C> {
    type Error = Error;

    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error> {
        let maybe_block = crate::rpc::query_block(&self.inner.client).await?;
        Ok(maybe_block.map(|b| b.height))
    }

    async fn fetch_shielded_transfers(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Error> {
        let _permit = self.inner.semaphore.acquire().await.unwrap();

        // Fetch all the transactions we do not have yet
        let mut txs = vec![];

        for height in from.0..=to.0 {
            let maybe_txs_results = async {
                get_indexed_masp_events_at_height(
                    &self.inner.client,
                    height.into(),
                )
                .await
            };

            let txs_results = maybe_txs_results.await?;
            if txs_results.is_empty() {
                continue;
            };

            let block = {
                self.inner
                    .client
                    .block(height as u32)
                    .await
                    .map_err(|e| {
                        Error::from(QueryError::General(e.to_string()))
                    })?
                    .block
                    .data
            };

            // Cache the last tx seen to avoid multiple deserializations
            let mut last_tx: Option<(Tx, TxIndex)> = None;

            for MaspEvent {
                tx_index,
                kind,
                data,
            } in txs_results
            {
                let tx = match &last_tx {
                    Some((tx, idx)) if idx == &tx_index.block_index => tx,
                    _ => {
                        let tx = Tx::try_from_bytes(
                            block[tx_index.block_index.0 as usize].as_ref(),
                        )
                        .map_err(|e| Error::Other(e.to_string()))?;
                        last_tx = Some((tx, tx_index.block_index));

                        &last_tx.as_ref().unwrap().0
                    }
                };
                let extracted_masp_tx = extract_masp_tx(tx, &data)
                    .map_err(|e| Error::Other(e.to_string()))?;

                txs.push((
                    MaspIndexedTx {
                        indexed_tx: tx_index,
                        kind: kind.into(),
                    },
                    extracted_masp_tx,
                ));
            }
        }

        Ok(txs)
    }

    #[inline(always)]
    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::OnlyTransfers
    }

    async fn fetch_commitment_tree(
        &self,
        _: BlockHeight,
    ) -> Result<CommitmentTree<Node>, Error> {
        Err(Error::Other(
            "Commitment tree fetching is not implemented by this client"
                .to_string(),
        ))
    }

    async fn fetch_note_index(
        &self,
        _: BlockHeight,
    ) -> Result<BTreeMap<MaspIndexedTx, usize>, Error> {
        Err(Error::Other(
            "Transaction notes map fetching is not implemented by this client"
                .to_string(),
        ))
    }

    async fn fetch_witness_map(
        &self,
        _: BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Error> {
        Err(Error::Other(
            "Witness map fetching is not implemented by this client"
                .to_string(),
        ))
    }

    async fn commitment_anchor_exists(
        &self,
        root: &Node,
    ) -> Result<bool, Error> {
        let anchor_key =
            crate::token::storage_key::masp_commitment_anchor_key(*root);
        crate::rpc::query_has_storage_key(&self.inner.client, &anchor_key).await
    }
}

#[derive(Debug)]
struct IndexerMaspClientShared {
    /// Limits open connections so as not to exhaust
    /// the connection limit at the OS level.
    semaphore: Semaphore,
    /// URL to the `namada-masp-indexer` API prefix (including `/api/v1`).
    indexer_api: reqwest::Url,
    /// Bloom filter to help avoid fetching block heights
    /// with no MASP notes.
    block_index: OnceCell<Option<(BlockHeight, xorf::BinaryFuse16)>>,
    /// Maximum number of concurrent fetches.
    max_concurrent_fetches: usize,
}

/// MASP client implementation that queries data from the
/// [`namada-masp-indexer`].
///
/// [`namada-masp-indexer`]: <https://github.com/anoma/namada-masp-indexer>
#[derive(Clone, Debug)]
pub struct IndexerMaspClient {
    client: reqwest::Client,
    shared: Arc<IndexerMaspClientShared>,
}

trait RequestBuilderExt {
    fn keep_alive(self) -> reqwest::RequestBuilder;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    #[inline(always)]
    fn keep_alive(self) -> reqwest::RequestBuilder {
        self.header("Connection", "Keep-Alive")
    }
}

impl IndexerMaspClient {
    /// Create a new [`IndexerMaspClient`].
    #[inline]
    pub fn new(
        client: reqwest::Client,
        indexer_api: reqwest::Url,
        using_block_index: bool,
        max_concurrent_fetches: usize,
    ) -> Self {
        let shared = Arc::new(IndexerMaspClientShared {
            indexer_api,
            max_concurrent_fetches,
            semaphore: Semaphore::new(max_concurrent_fetches),
            block_index: OnceCell::new_with(
                (!using_block_index).then_some(None),
            ),
        });
        Self { client, shared }
    }

    fn endpoint(&self, which: &str) -> String {
        format!("{}{which}", self.shared.indexer_api)
    }

    async fn get_server_error(
        response: reqwest::Response,
    ) -> Result<String, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            message: String,
        }

        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize server's error JSON response: {err}"
            ))
        })?;

        Ok(payload.message)
    }

    async fn last_block_index(
        &self,
    ) -> Result<(BlockHeight, xorf::BinaryFuse16), Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            block_height: u64,
            index: xorf::BinaryFuse16,
        }

        let _permit = self.shared.semaphore.acquire().await.unwrap();

        let response = self
            .client
            .get(self.endpoint("/block-index"))
            .keep_alive()
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch latest masp tx block index: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch latest masp tx block index: {err}"
            )));
        }
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize latest masp tx block index JSON \
                 response: {err}"
            ))
        })?;

        Ok((BlockHeight(payload.block_height), payload.index))
    }
}

impl MaspClient for IndexerMaspClient {
    type Error = Error;

    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            block_height: u64,
        }

        let _permit = self.shared.semaphore.acquire().await.unwrap();

        let response = self
            .client
            .get(self.endpoint("/height"))
            .keep_alive()
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch latest block height: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch last block height: {err}"
            )));
        }
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize latest block height JSON response: \
                 {err}"
            ))
        })?;

        Ok(if payload.block_height != 0 {
            Some(BlockHeight(payload.block_height))
        } else {
            None
        })
    }

    async fn fetch_shielded_transfers(
        &self,
        BlockHeight(mut from): BlockHeight,
        BlockHeight(to): BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Error> {
        use std::ops::ControlFlow;

        use futures::stream::{self, StreamExt};
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct TransactionSlot {
            masp_tx_index: u64,
            is_masp_fee_payment: bool,
            bytes: Vec<u8>,
        }

        #[derive(Deserialize)]
        struct Transaction {
            block_height: u64,
            block_index: u64,
            batch: Vec<TransactionSlot>,
        }

        #[derive(Deserialize)]
        struct TxResponse {
            txs: Vec<Transaction>,
        }

        if from > to {
            return Err(Error::Other(format!(
                "Invalid block range {from}-{to}: Beginning height {from} is \
                 greater than ending height {to}"
            )));
        }

        let maybe_block_index: &Option<_> = self
            .shared
            .block_index
            .get_or_init(|| async { self.last_block_index().await.ok() })
            .await;

        let mut fetches = vec![];
        loop {
            'do_while: {
                const MAX_RANGE_THRES: u64 = 30;

                let mut from_height = from;
                let mut offset = (to - from).min(MAX_RANGE_THRES);
                let mut to_height = from + offset;
                from += offset;

                // if the bloom filter has finished downloading, we can
                // use it to avoid unnecessary fetches of block heights
                // that contain no MASP notes.
                //
                // * `block_index_height` is the height at which the filter was
                //   built.
                // * `block_index` is the actual bloom filter.
                if let Some((BlockHeight(block_index_height), block_index)) =
                    maybe_block_index
                {
                    match BlockIndex::check_block_index(
                        *block_index_height,
                        from_height,
                        to_height,
                    )
                    .needs_to_fetch(block_index)
                    {
                        ControlFlow::Break(()) => {
                            // We do not need to fetch this range.
                            //
                            // NB: skips code below, so it's more like a
                            // `continue`
                            break 'do_while;
                        }
                        ControlFlow::Continue((from, to)) => {
                            // the sub-range which we need to fetch.
                            from_height = from;
                            to_height = to;
                            offset = to_height - from_height;
                        }
                    }
                }

                fetches.push(async move {
                    let _permit =
                        self.shared.semaphore.acquire().await.unwrap();

                    let payload: TxResponse = {
                        let response = self
                            .client
                            .get(self.endpoint("/tx"))
                            .keep_alive()
                            .query(&[
                                ("height", from_height),
                                ("height_offset", offset),
                            ])
                            .send()
                            .await
                            .map_err(|err| {
                                Error::Other(format!(
                                    "Failed to fetch transactions in the \
                                     height range {from_height}-{to_height}: \
                                     {err}"
                                ))
                            })?;
                        if !response.status().is_success() {
                            let err = Self::get_server_error(response).await?;
                            return Err(Error::Other(format!(
                                "Failed to fetch transactions in the range \
                                 {from_height}-{to_height}: {err}"
                            )));
                        }
                        response.json().await.map_err(|err| {
                            Error::Other(format!(
                                "Could not deserialize the transactions JSON \
                                 response in the height range \
                                 {from_height}-{to_height}: {err}"
                            ))
                        })?
                    };

                    Ok(payload.txs)
                });
            }

            if from >= to {
                break;
            }
        }

        let mut stream_of_fetches = stream::iter(fetches)
            .buffer_unordered(self.shared.max_concurrent_fetches);
        let mut txs = vec![];

        while let Some(result) = stream_of_fetches.next().await {
            for Transaction {
                block_height,
                block_index,
                batch: transactions,
            } in result?
            {
                for slot in transactions {
                    let extracted_masp_tx = MaspTx::try_from_slice(&slot.bytes)
                        .map_err(|err| {
                            Error::Other(format!(
                                "Could not deserialize the masp txs borsh \
                                 data at height {}, block index {} and batch \
                                 index: {:#?}: {err}",
                                block_height, block_index, slot.masp_tx_index
                            ))
                        })?;

                    let kind = if slot.is_masp_fee_payment {
                        MaspTxKind::FeePayment
                    } else {
                        MaspTxKind::Transfer
                    };
                    let masp_indexed_tx = MaspIndexedTx {
                        kind,
                        indexed_tx: IndexedTx {
                            block_height: block_height.into(),
                            block_index: TxIndex::must_from_usize(
                                block_index as usize,
                            ),
                            batch_index: Some(slot.masp_tx_index as u32),
                        },
                    };
                    txs.push((masp_indexed_tx, extracted_masp_tx));
                }
            }
        }

        Ok(txs)
    }

    #[inline(always)]
    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::AllData
    }

    async fn fetch_commitment_tree(
        &self,
        BlockHeight(height): BlockHeight,
    ) -> Result<CommitmentTree<Node>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            commitment_tree: Vec<u8>,
        }

        let _permit = self.shared.semaphore.acquire().await.unwrap();

        let response = self
            .client
            .get(self.endpoint("/commitment-tree"))
            .keep_alive()
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch commitment tree at height {height}: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch commitment tree at height {height}: {err}"
            )));
        }
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize the commitment tree JSON response at \
                 height {height}: {err}"
            ))
        })?;

        BorshDeserialize::try_from_slice(&payload.commitment_tree).map_err(
            |err| {
                Error::Other(format!(
                    "Could not deserialize the commitment tree borsh data at \
                     height {height}: {err}"
                ))
            },
        )
    }

    async fn fetch_note_index(
        &self,
        BlockHeight(height): BlockHeight,
    ) -> Result<BTreeMap<MaspIndexedTx, usize>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Note {
            note_position: usize,
            #[serde(rename = "masp_tx_index")]
            batch_index: u32,
            block_index: u32,
            block_height: u64,
            is_masp_fee_payment: bool,
        }

        #[derive(Deserialize)]
        struct Response {
            notes_index: Vec<Note>,
        }

        let _permit = self.shared.semaphore.acquire().await.unwrap();

        let response = self
            .client
            .get(self.endpoint("/notes-index"))
            .keep_alive()
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch notes map at height {height}: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch notes map at height {height}: {err}"
            )));
        }
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize the notes map JSON response at height \
                 {height}: {err}"
            ))
        })?;

        let mut masp_index = 0;
        let mut prev_block_height = None;

        Ok(payload
            .notes_index
            .into_iter()
            .map(
                |Note {
                     block_index,
                     batch_index,
                     block_height,
                     note_position,
                     is_masp_fee_payment,
                 }| {
                    if Some(block_height) != prev_block_height {
                        masp_index = 0;
                        prev_block_height = Some(block_height);
                    } else {
                        masp_index += 1;
                    }
                    (
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_index: TxIndex(block_index),
                                block_height: BlockHeight(block_height),
                                batch_index: Some(batch_index),
                            },
                            kind: if is_masp_fee_payment {
                                MaspTxKind::FeePayment
                            } else {
                                MaspTxKind::Transfer
                            },
                        },
                        note_position,
                    )
                },
            )
            .collect())
    }

    async fn fetch_witness_map(
        &self,
        BlockHeight(height): BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Witness {
            bytes: Vec<u8>,
            index: usize,
        }

        #[derive(Deserialize)]
        struct WitnessMapResponse {
            witnesses: Vec<Witness>,
        }

        let _permit = self.shared.semaphore.acquire().await.unwrap();

        let response = self
            .client
            .get(self.endpoint("/witness-map"))
            .keep_alive()
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch witness map at height {height}: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch witness map at height {height}: {err}"
            )));
        }
        let payload: WitnessMapResponse =
            response.json().await.map_err(|err| {
                Error::Other(format!(
                    "Could not deserialize the witness map JSON response at \
                     height {height}: {err}"
                ))
            })?;

        payload.witnesses.into_iter().try_fold(
            HashMap::new(),
            |mut accum, Witness { index, bytes }| {
                let witness = BorshDeserialize::try_from_slice(&bytes)
                    .map_err(|err| {
                        Error::Other(format!(
                            "Could not deserialize the witness borsh data at \
                             height {height}: {err}"
                        ))
                    })?;
                accum.insert(index, witness);
                Ok(accum)
            },
        )
    }

    async fn commitment_anchor_exists(
        &self,
        _root: &Node,
    ) -> Result<bool, Error> {
        Err(Error::Other(
            "Commitment anchor checking is not implemented by this client"
                .to_string(),
        ))
    }
}

#[derive(Copy, Clone)]
#[allow(clippy::enum_variant_names)]
enum BlockIndex {
    BelowRange {
        from: u64,
        to: u64,
    },
    InRange {
        from: u64,
        to: u64,
        block_index_height: u64,
    },
    AboveRange {
        from: u64,
        to: u64,
    },
}

impl BlockIndex {
    /// Get the sub-range or [`from`, `to`]  for which a [`BlockIndex`]
    /// built at height `block_index_height` is applicable.
    fn check_block_index(
        block_index_height: u64,
        from: u64,
        to: u64,
    ) -> BlockIndex {
        // applicable to whole range
        if block_index_height > to {
            return BlockIndex::AboveRange { from, to };
        }
        // applicable to none of the range
        if block_index_height < from {
            return BlockIndex::BelowRange { from, to };
        }
        // applicable to range [`from`, `block_index_height`]
        BlockIndex::InRange {
            from,
            to,
            block_index_height,
        }
    }

    /// Narrow the requested range to only those blocks
    /// containing MASP notes.
    fn needs_to_fetch(
        self,
        block_index: &xorf::BinaryFuse16,
    ) -> std::ops::ControlFlow<(), (u64, u64)> {
        use std::ops::ControlFlow;

        use xorf::Filter;

        match self {
            Self::BelowRange { from, to } => ControlFlow::Continue((from, to)),
            Self::InRange {
                from,
                block_index_height,
                to,
            } => {
                let lowest_height_in_index = (from..=block_index_height)
                    .find(|height| block_index.contains(height));

                match lowest_height_in_index {
                    Some(from_height_in_index) => {
                        ControlFlow::Continue((from_height_in_index, to))
                    }
                    None if block_index_height == to => ControlFlow::Break(()),
                    None => ControlFlow::Continue((block_index_height + 1, to)),
                }
            }
            Self::AboveRange { from, to } => {
                // drop from the beginning of the range
                let lowest_height_in_index =
                    (from..=to).find(|height| block_index.contains(height));

                // drop from the end of the range
                let maybe_bounds =
                    lowest_height_in_index.and_then(|lowest_height_in_index| {
                        let highest_height_in_index = (from..=to)
                            .rev()
                            .find(|height| block_index.contains(height))?;

                        Some((lowest_height_in_index, highest_height_in_index))
                    });

                if let Some((from, to)) = maybe_bounds {
                    ControlFlow::Continue((from, to))
                } else {
                    ControlFlow::Break(())
                }
            }
        }
    }
}

async fn with_linear_backoff<F, T, E>(
    backoff: &RwLock<Duration>,
    sleep: &Sleep<LinearBackoff>,
    fut: F,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    const ZERO: Duration = Duration::from_secs(0);
    let current_backoff = { *backoff.read().unwrap() };

    if current_backoff > ZERO {
        sleep.sleep_with_current_backoff(&current_backoff).await;
    }

    let result = fut.await;

    if result.is_err() {
        let mut backoff = backoff.write().unwrap();
        sleep.strategy.next_state(&mut *backoff);
    } else if current_backoff > ZERO {
        let mut backoff = backoff.write().unwrap();
        sleep.strategy.prev_state(&mut *backoff);
    }

    result
}

#[cfg(test)]
mod test_block_index {
    use std::ops::ControlFlow;

    use proptest::proptest;

    use super::BlockIndex;

    /// An arbitrary filter
    fn block_filter() -> xorf::BinaryFuse16 {
        vec![10u64, 12, 14, 16, 18, 20]
            .try_into()
            .expect("Test failed")
    }

    proptest! {
        #[test]
        fn test_needs_to_fetch_below_range(to in 0..=9u64) {
            let block_index = BlockIndex::BelowRange { from: 0, to};
            let ControlFlow::Continue((0, upper)) = block_index.needs_to_fetch(&block_filter()) else {
                panic!("Test failed");
            };
            assert_eq!(upper, to);
        }
    }

    #[test]
    fn test_needs_to_fetch_in_range() {
        let block_index = BlockIndex::InRange {
            from: 0,
            to: 30,
            block_index_height: 15,
        };

        let empty_filter: xorf::BinaryFuse16 =
            vec![].try_into().expect("Test failed");
        let ControlFlow::Continue((16, 30)) =
            block_index.needs_to_fetch(&empty_filter)
        else {
            panic!("Test failed");
        };

        let ControlFlow::Continue((10, 30)) =
            block_index.needs_to_fetch(&block_filter())
        else {
            panic!("Test failed");
        };

        let block_index = BlockIndex::InRange {
            from: 15,
            to: 15,
            block_index_height: 15,
        };
        let ControlFlow::Break(()) =
            block_index.needs_to_fetch(&block_filter())
        else {
            panic!("Test failed");
        };

        let block_index = BlockIndex::InRange {
            from: 14,
            to: 14,
            block_index_height: 14,
        };
        let ControlFlow::Continue((14, 14)) =
            block_index.needs_to_fetch(&block_filter())
        else {
            panic!("Test failed");
        };
    }

    #[test]
    fn test_needs_to_fetch_above_range() {
        let block_index = BlockIndex::AboveRange { from: 10, to: 20 };
        let ControlFlow::Continue((10, 20)) =
            block_index.needs_to_fetch(&block_filter())
        else {
            panic!("Test failed");
        };

        let block_index = BlockIndex::AboveRange { from: 0, to: 20 };
        let ControlFlow::Continue((10, 20)) =
            block_index.needs_to_fetch(&block_filter())
        else {
            panic!("Test failed");
        };

        let block_index = BlockIndex::AboveRange { from: 10, to: 30 };
        let ControlFlow::Continue((10, 20)) =
            block_index.needs_to_fetch(&block_filter())
        else {
            panic!("Test failed");
        };

        let block_index = BlockIndex::AboveRange { from: 0, to: 30 };
        let ControlFlow::Continue((10, 20)) =
            block_index.needs_to_fetch(&block_filter())
        else {
            panic!("Test failed");
        };

        let block_index = BlockIndex::AboveRange { from: 11, to: 11 };
        let ControlFlow::Break(()) =
            block_index.needs_to_fetch(&block_filter())
        else {
            panic!("Test failed");
        };

        let block_index = BlockIndex::AboveRange { from: 12, to: 12 };
        let ControlFlow::Continue((12, 12)) =
            block_index.needs_to_fetch(&block_filter())
        else {
            panic!("Test failed");
        };

        let block_index = BlockIndex::AboveRange { from: 11, to: 19 };
        let ControlFlow::Continue((12, 18)) =
            block_index.needs_to_fetch(&block_filter())
        else {
            panic!("Test failed");
        };
    }
}
