use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::FutureExt;
use namada_sdk::chain::BlockHeight;
use namada_sdk::state::ProcessProposalCachedResult;
use namada_sdk::tendermint::abci::request::CheckTxKind;
use namada_sdk::tendermint::abci::response::ProcessProposal;
use namada_sdk::time::{DateTimeUtc, Utc};
use tokio::sync::broadcast;

use super::ShellMode;
use crate::config::{Action, ActionAtHeight};
use crate::shell::{Error, MempoolTxType, Shell};
use crate::shims::abcipp_shim_types::shim::request::{
    FinalizeBlock, ProcessedTx,
};
use crate::shims::abcipp_shim_types::shim::{
    Error as ShimErr, Request, Response,
};
use crate::tendermint::abci::{Request as Req, Response as Resp, response};
use crate::tower_abci::BoxError;
use crate::{config, shims};

/// Run the shell's blocking loop that receives messages from the receiver.
pub fn shell_loop(
    mut shell: Shell,
    mut shell_recv: tokio::sync::mpsc::UnboundedReceiver<ReqMsg>,
    namada_version: &str,
) {
    while let Some((req, resp_sender)) = shell_recv.blocking_recv() {
        let resp = match req {
            Req::ProcessProposal(proposal) => process_request(
                &mut shell,
                Request::ProcessProposal(proposal),
                namada_version,
            )
            .map_err(ShimErr::from)
            .and_then(|resp| resp.try_into()),
            Req::FinalizeBlock(mut request) => {
                match shell.get_process_proposal_result(request.clone()) {
                    ProcessProposalCachedResult::Accepted(tx_results) => {
                        let mut txs = Vec::with_capacity(tx_results.len());
                        for (result, tx) in tx_results
                            .into_iter()
                            .zip(std::mem::take(&mut request.txs).into_iter())
                        {
                            txs.push(ProcessedTx {
                                tx,
                                result: result.into(),
                            });
                        }
                        let mut request: FinalizeBlock = request.into();
                        request.txs = txs;
                        process_request(
                            &mut shell,
                            Request::FinalizeBlock(request),
                            namada_version,
                        )
                        .map_err(ShimErr::from)
                        .and_then(|res| match res {
                            Response::FinalizeBlock(resp) => {
                                Ok(Resp::FinalizeBlock(resp.into()))
                            }
                            _ => Err(ShimErr::ConvertResp(res)),
                        })
                    }
                    ProcessProposalCachedResult::Rejected => {
                        Err(ShimErr::Shell(
                            crate::shell::Error::RejectedBlockProposal,
                        ))
                    }
                }
            }
            Req::Commit => {
                match process_request(
                    &mut shell,
                    Request::Commit,
                    namada_version,
                ) {
                    Ok(Response::Commit(res)) => {
                        let take_snapshot = shell.check_snapshot_required();
                        shell.update_snapshot_task(take_snapshot);
                        Ok(Resp::Commit(res))
                    }
                    Ok(resp) => Err(ShimErr::ConvertResp(resp)),
                    Err(e) => Err(ShimErr::Shell(e)),
                }
            }
            _ => match Request::try_from(req.clone()) {
                Ok(request) => {
                    process_request(&mut shell, request, namada_version)
                        .map(Resp::try_from)
                        .map_err(ShimErr::Shell)
                        .and_then(|inner| inner)
                }
                Err(err) => Err(err),
            },
        };

        let resp = resp.map_err(|e| e.into());
        if resp_sender.send(resp).is_err() {
            tracing::info!("ABCI response channel is closed")
        }
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
        Request::VerifyHeader(_req) => {
            Ok(Response::VerifyHeader(shell.verify_header(_req)))
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
                let result = if let ProcessProposal::Accept = response {
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
        Request::RevertProposal(_req) => {
            Ok(Response::RevertProposal(shell.revert_proposal(_req)))
        }
        Request::FinalizeBlock(finalize) => {
            tracing::debug!("Request FinalizeBlock");

            try_recheck_process_proposal(shell, &finalize)?;
            shell.finalize_block(finalize).map(Response::FinalizeBlock)
        }
        Request::Commit => {
            tracing::debug!("Request Commit");
            Ok(Response::Commit(shell.commit()))
        }
        Request::Flush => Ok(Response::Flush),
        Request::Echo(msg) => Ok(Response::Echo(response::Echo {
            message: msg.message,
        })),
        Request::CheckTx(tx) => {
            let mempool_tx_type = match tx.kind {
                CheckTxKind::New => MempoolTxType::NewTransaction,
                CheckTxKind::Recheck => MempoolTxType::RecheckTransaction,
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

pub type ReqMsg = (Req, tokio::sync::oneshot::Sender<Result<Resp, BoxError>>);

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
    ) -> (bool, Option<<Self as tower::Service<Req>>::Future>) {
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
        req: Req,
    ) -> <Self as tower::Service<Req>>::Future {
        let (resp_send, recv) = tokio::sync::oneshot::channel();
        let result = self.shell_send.send((req.clone(), resp_send));
        async move {
            let genesis_time = if let Req::InitChain(ref init) = req {
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
    fn get_action(&self, req: &Req) -> Option<CheckAction> {
        match req {
            Req::PrepareProposal(req) => {
                Some(CheckAction::Check(req.height.into())) // TODO switch to u64?
            }
            Req::ProcessProposal(req) => {
                Some(CheckAction::Check(req.height.into()))
            }
            Req::FinalizeBlock(req) => {
                Some(CheckAction::Check(req.height.into()))
            }
            Req::InitChain(_) | Req::CheckTx(_) | Req::Commit => {
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
/// from the [`AbcippShim`] for requests from Tendermint.
impl tower::Service<Req> for Service {
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Resp, BoxError>> + Send + 'static>>;
    type Response = Resp;

    fn poll_ready(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        // Nothing to check as the sender's channel is unbounded
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Req) -> Self::Future {
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
    finalize_req: &shims::abcipp_shim_types::shim::request::FinalizeBlock,
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
            .get(&finalize_req.block_hash)
        {
            // We already have the result of process proposal for this block
            // cached in memory
            Some(res) => res.to_owned(),
            None => {
                let process_req = finalize_req
                    .clone()
                    .cast_to_process_proposal_req()
                    .map_err(|_| Error::InvalidBlockProposal)?;
                // No need to cache the result since this is the last step
                // before finalizing the block
                if let ProcessProposal::Accept =
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
