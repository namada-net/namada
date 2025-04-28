use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::FutureExt;
use namada_sdk::chain::BlockHeight;
use namada_sdk::hash::Hash;
use namada_sdk::state::ProcessProposalCachedResult;
use namada_sdk::time::{DateTimeUtc, Utc};
use tokio::sync::broadcast;

use super::ShellMode;
use crate::config::{Action, ActionAtHeight};
use crate::shell::{Error, MempoolTxType, Shell, finalize_block};
use crate::tendermint::abci::{Request, Response};
pub use crate::tendermint::abci::{request, response};
use crate::tower_abci::BoxError;
use crate::{config, tendermint};

/// Run the shell's blocking loop that receives messages from the receiver.
pub fn shell_loop(
    mut shell: Shell,
    mut shell_recv: tokio::sync::mpsc::UnboundedReceiver<ReqMsg>,
    namada_version: &str,
) {
    while let Some((req, resp_sender)) = shell_recv.blocking_recv() {
        let resp = process_request(&mut shell, req, namada_version)
            .map_err(|e| e.into());
        if resp_sender.send(resp).is_err() {
            tracing::info!("ABCI response channel is closed")
        }
    }
}

pub type TxBytes = prost::bytes::Bytes;

/// A Tx and the result of calling Process Proposal on it
#[derive(Debug, Clone)]
pub struct ProcessedTx {
    pub tx: TxBytes,
    pub result: TxResult,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct TxResult {
    pub code: u32,
    pub info: String,
}

impl From<(u32, String)> for TxResult {
    fn from((code, info): (u32, String)) -> Self {
        Self { code, info }
    }
}

impl From<TxResult> for (u32, String) {
    fn from(TxResult { code, info }: TxResult) -> Self {
        (code, info)
    }
}

fn process_request(
    shell: &mut Shell,
    req: Request,
    namada_version: &str,
) -> Result<Response, Error> {
    match req {
        Request::InitChain(init) => {
            tracing::debug!("Request InitChain");
            shell
                .init_chain(
                    init,
                    #[cfg(any(
                        test,
                        feature = "testing",
                        feature = "benches"
                    ))]
                    1,
                )
                .map(Response::InitChain)
        }
        Request::Info(_) => {
            Ok(Response::Info(shell.last_state(namada_version)))
        }
        Request::Query(query) => Ok(Response::Query(shell.query(query))),
        Request::PrepareProposal(block) => {
            tracing::debug!("Request PrepareProposal");
            // TODO: use TM domain type in the handler
            Ok(Response::PrepareProposal(
                shell.prepare_proposal(block.into()),
            ))
        }
        Request::ProcessProposal(block) => {
            tracing::debug!("Request ProcessProposal");
            // TODO: use TM domain type in the handler
            // NOTE: make sure to put any checks inside process_proposal
            // since that function is called in other places to rerun the
            // checks if (when) needed. Every check living outside that
            // function will not be correctly replicated in the other
            // locations
            let block_hash = block.hash.try_into();
            let (response, tx_results) = shell.process_proposal(block.into());
            // Cache the response in case of future calls from Namada. If
            // hash conversion fails avoid caching
            if let Ok(block_hash) = block_hash {
                let result = if let response::ProcessProposal::Accept = response
                {
                    ProcessProposalCachedResult::Accepted(
                        tx_results.into_iter().map(|res| res.into()).collect(),
                    )
                } else {
                    ProcessProposalCachedResult::Rejected
                };

                shell
                    .state
                    .in_mem_mut()
                    .block_proposals_cache
                    .put(block_hash, result);
            }
            Ok(Response::ProcessProposal(response))
        }
        Request::FinalizeBlock(request) => {
            tracing::debug!("Request FinalizeBlock");

            match shell.get_process_proposal_result(request.clone()) {
                ProcessProposalCachedResult::Accepted(tx_results) => {
                    try_recheck_process_proposal(shell, &request)?;

                    let request::FinalizeBlock {
                        txs,
                        decided_last_commit,
                        misbehavior,
                        hash,
                        height,
                        time,
                        next_validators_hash,
                        proposer_address,
                    } = request;

                    let mut processed_txs =
                        Vec::with_capacity(tx_results.len());
                    for (result, tx) in
                        tx_results.into_iter().zip(txs.into_iter())
                    {
                        processed_txs.push(ProcessedTx {
                            tx,
                            result: result.into(),
                        });
                    }

                    #[allow(clippy::disallowed_methods)]
                    let hash =
                        Hash::try_from(hash.as_bytes()).unwrap_or_default();
                    #[allow(clippy::disallowed_methods)]
                    let time = DateTimeUtc::try_from(time).unwrap();
                    let next_validators_hash =
                        next_validators_hash.try_into().unwrap();
                    let height = BlockHeight::from(height);
                    let request = finalize_block::Request {
                        txs: processed_txs,
                        decided_last_commit,
                        misbehavior,
                        hash,
                        height,
                        time,
                        next_validators_hash,
                        proposer_address,
                    };
                    shell.finalize_block(request).map(
                        |finalize_block::Response {
                             events,
                             tx_results,
                             validator_updates,
                         }| {
                            Response::FinalizeBlock(response::FinalizeBlock {
                                events: events
                                    .into_iter()
                                    .map(tendermint::abci::Event::from)
                                    .collect(),
                                tx_results,
                                validator_updates,
                                consensus_param_updates: None,
                                app_hash: Default::default(),
                            })
                        },
                    )
                }
                ProcessProposalCachedResult::Rejected => {
                    Err(Error::RejectedBlockProposal)
                }
            }
        }
        Request::Commit => {
            tracing::debug!("Request Commit");
            let response = shell.commit();
            let take_snapshot = shell.check_snapshot_required();
            shell.update_snapshot_task(take_snapshot);
            Ok(Response::Commit(response))
        }
        Request::Flush => Ok(Response::Flush),
        Request::Echo(msg) => Ok(Response::Echo(response::Echo {
            message: msg.message,
        })),
        Request::CheckTx(tx) => {
            let mempool_tx_type = match tx.kind {
                request::CheckTxKind::New => MempoolTxType::NewTransaction,
                request::CheckTxKind::Recheck => {
                    MempoolTxType::RecheckTransaction
                }
            };
            let r#type = mempool_tx_type;
            Ok(Response::CheckTx(shell.mempool_validate(&tx.tx, r#type)))
        }
        Request::ListSnapshots => {
            Ok(Response::ListSnapshots(shell.list_snapshots()))
        }
        Request::OfferSnapshot(req) => {
            Ok(Response::OfferSnapshot(shell.offer_snapshot(req)))
        }
        Request::LoadSnapshotChunk(req) => {
            Ok(Response::LoadSnapshotChunk(shell.load_snapshot_chunk(req)))
        }
        Request::ApplySnapshotChunk(req) => Ok(Response::ApplySnapshotChunk(
            shell.apply_snapshot_chunk(req),
        )),
        Request::ExtendVote(_req) => {
            Ok(Response::ExtendVote(response::ExtendVote {
                vote_extension: bytes::Bytes::new(),
            }))
        }
        Request::VerifyVoteExtension(_verify_vote_extension) => {
            Ok(Response::VerifyVoteExtension(
                response::VerifyVoteExtension::Reject,
            ))
        }
    }
}

#[derive(Debug)]
pub struct Service {
    /// A channel for forwarding requests to the shell
    shell_send: tokio::sync::mpsc::UnboundedSender<ReqMsg>,
    /// Indicates if the consensus connection is suspended.
    suspended: bool,
    /// This resolves the non-completing futures returned to tower-abci
    /// during suspension.
    shutdown: broadcast::Sender<()>,
    /// An action to be taken at a specified block height.
    action_at_height: Option<ActionAtHeight>,
}

pub type ReqMsg = (
    Request,
    tokio::sync::oneshot::Sender<Result<Response, BoxError>>,
);

/// Indicates how [`Service`] should check whether or not it needs to take
/// action.
#[derive(Debug)]
enum CheckAction {
    /// No check necessary.
    NoAction,
    /// Check a given block height.
    Check(i64),
    /// The action been taken.
    AlreadySuspended,
}

impl Service {
    /// Create a shell with a ABCI service that passes messages to and from the
    /// shell.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &config::Ledger,
    ) -> (
        Self,
        tokio::sync::mpsc::UnboundedReceiver<ReqMsg>,
        broadcast::Sender<()>,
    ) {
        let (shell_send, shell_recv) =
            tokio::sync::mpsc::unbounded_channel::<ReqMsg>();
        let (server_shutdown, _) = broadcast::channel::<()>(1);
        let action_at_height = config.shell.action_at_height.clone();
        (
            Self {
                shell_send,
                shutdown: server_shutdown.clone(),
                action_at_height,
                suspended: false,
            },
            shell_recv,
            server_shutdown,
        )
    }

    /// Check if we are at a block height with a scheduled action.
    /// If so, perform the action.
    fn maybe_take_action(
        action_at_height: Option<ActionAtHeight>,
        check: CheckAction,
        mut shutdown_recv: broadcast::Receiver<()>,
    ) -> (bool, Option<<Self as tower::Service<Request>>::Future>) {
        let hght = match check {
            CheckAction::AlreadySuspended => BlockHeight::from(u64::MAX),
            CheckAction::Check(hght) => BlockHeight::from(
                u64::try_from(hght).expect("Height cannot be negative"),
            ),
            CheckAction::NoAction => BlockHeight::default(),
        };
        match action_at_height {
            Some(ActionAtHeight {
                height,
                action: Action::Suspend,
            }) if height <= hght => {
                if height == hght {
                    tracing::info!(
                        "Reached block height {}, suspending.",
                        height
                    );
                    tracing::warn!(
                        "\x1b[93mThis feature is intended for debugging \
                         purposes. Note that on shutdown a spurious panic \
                         message will be produced.\x1b[0m"
                    )
                }
                (
                    true,
                    Some(
                        async move {
                            shutdown_recv.recv().await.unwrap();
                            Err(BoxError::from(
                                "Not all tendermint responses were processed. \
                                 If the `--suspended` flag was passed, you \
                                 may ignore this error.",
                            ))
                        }
                        .boxed(),
                    ),
                )
            }
            Some(ActionAtHeight {
                height,
                action: Action::Halt,
            }) if height == hght => {
                tracing::info!(
                    "Reached block height {}, halting the chain.",
                    height
                );
                (
                    false,
                    Some(
                        async move {
                            Err(BoxError::from(format!(
                                "Reached block height {}, halting the chain.",
                                height
                            )))
                        }
                        .boxed(),
                    ),
                )
            }
            _ => (false, None),
        }
    }

    /// If we are not taking special action for this request, forward it
    /// normally.
    fn forward_request(
        &mut self,
        req: Request,
    ) -> <Self as tower::Service<Request>>::Future {
        let (resp_send, recv) = tokio::sync::oneshot::channel();
        let result = self.shell_send.send((req.clone(), resp_send));
        async move {
            let genesis_time = if let Request::InitChain(ref init) = req {
                Some(
                    DateTimeUtc::try_from(init.time)
                        .expect("Should be able to parse genesis time."),
                )
            } else {
                None
            };
            if let Err(err) = result {
                // The shell has shut-down
                return Err(err.into());
            }
            recv.await
                .unwrap_or_else(|err| {
                    tracing::info!("ABCI response channel didn't respond");
                    Err(err.into())
                })
                .inspect(|_| {
                    // emit a log line stating that we are sleeping until
                    // genesis.
                    #[allow(clippy::disallowed_methods)]
                    let now = Utc::now();
                    if let Some(Ok(sleep_time)) = genesis_time
                        .map(|t| t.0.signed_duration_since(now).to_std())
                    {
                        if !sleep_time.is_zero() {
                            tracing::info!(
                                "Waiting for ledger genesis time: {:?}, time \
                                 left: {:?}",
                                genesis_time.unwrap(),
                                sleep_time
                            );
                        }
                    }
                })
        }
        .boxed()
    }

    /// Given the type of request, determine if we need to check
    /// to possibly take an action.
    fn get_action(&self, req: &Request) -> Option<CheckAction> {
        match req {
            Request::PrepareProposal(req) => {
                Some(CheckAction::Check(req.height.into())) // TODO switch to u64?
            }
            Request::ProcessProposal(req) => {
                Some(CheckAction::Check(req.height.into()))
            }
            Request::FinalizeBlock(req) => {
                Some(CheckAction::Check(req.height.into()))
            }
            Request::InitChain(_) | Request::CheckTx(_) | Request::Commit => {
                if self.suspended {
                    Some(CheckAction::AlreadySuspended)
                } else {
                    Some(CheckAction::NoAction)
                }
            }
            _ => None,
        }
    }
}

/// The ABCI tower service implementation sends and receives messages to and
/// from the [`Service`] for requests from Tendermint.
impl tower::Service<Request> for Service {
    type Error = BoxError;
    type Future = Pin<
        Box<dyn Future<Output = Result<Response, BoxError>> + Send + 'static>,
    >;
    type Response = Response;

    fn poll_ready(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        // Nothing to check as the sender's channel is unbounded
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let action = self.get_action(&req);
        if let Some(action) = action {
            let (suspended, fut) = Self::maybe_take_action(
                self.action_at_height.clone(),
                action,
                self.shutdown.subscribe(),
            );
            self.suspended = suspended;
            fut.unwrap_or_else(|| self.forward_request(req))
        } else {
            self.forward_request(req)
        }
    }
}

// Checks if a run of process proposal is required before finalize block
// (recheck) and, in case, performs it. Clears the cache before returning
fn try_recheck_process_proposal(
    shell: &mut Shell,
    finalize_req: &tendermint::abci::request::FinalizeBlock,
) -> Result<(), Error> {
    let recheck_process_proposal = match shell.mode {
        ShellMode::Validator {
            ref local_config, ..
        } => local_config
            .as_ref()
            .map(|cfg| cfg.recheck_process_proposal)
            .unwrap_or_default(),
        ShellMode::Full { ref local_config } => local_config
            .as_ref()
            .map(|cfg| cfg.recheck_process_proposal)
            .unwrap_or_default(),
        ShellMode::Seed => false,
    };

    if recheck_process_proposal {
        let process_proposal_result = match shell
            .state
            .in_mem_mut()
            .block_proposals_cache
            .get(&Hash::try_from(finalize_req.hash).unwrap())
        {
            // We already have the result of process proposal for this block
            // cached in memory
            Some(res) => res.to_owned(),
            None => {
                let process_req =
                    finalize_block_to_process_proposal(finalize_req.clone());
                // No need to cache the result since this is the last step
                // before finalizing the block
                if let response::ProcessProposal::Accept =
                    shell.process_proposal(process_req.into()).0
                {
                    ProcessProposalCachedResult::Accepted(vec![])
                } else {
                    ProcessProposalCachedResult::Rejected
                }
            }
        };

        if let ProcessProposalCachedResult::Rejected = process_proposal_result {
            return Err(Error::RejectedBlockProposal);
        }
    }

    // Clear the cache of proposed blocks' results
    shell.state.in_mem_mut().block_proposals_cache.clear();

    Ok(())
}

pub fn finalize_block_to_process_proposal(
    req: request::FinalizeBlock,
) -> request::ProcessProposal {
    let request::FinalizeBlock {
        txs,
        decided_last_commit,
        misbehavior,
        hash,
        height,
        time,
        next_validators_hash,
        proposer_address,
    } = req;
    request::ProcessProposal {
        txs,
        proposed_last_commit: Some(decided_last_commit),
        misbehavior,
        hash,
        height,
        time,
        next_validators_hash,
        proposer_address,
    }
}
