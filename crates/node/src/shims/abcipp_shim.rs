use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::FutureExt;
use namada_apps_lib::state::DbError;
use namada_sdk::chain::BlockHeight;
use namada_sdk::migrations::ScheduledMigration;
use namada_sdk::state::ProcessProposalCachedResult;
use namada_sdk::tendermint::abci::response::ProcessProposal;
use namada_sdk::time::{DateTimeUtc, Utc};
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedSender;
use tower::Service;

use super::abcipp_shim_types::shim::request::{
    CheckProcessProposal, FinalizeBlock, ProcessedTx,
};
use super::abcipp_shim_types::shim::{Error, Request, Response};
use crate::config;
use crate::config::{Action, ActionAtHeight};
use crate::shell::{EthereumOracleChannels, Shell, TakeSnapshot};
use crate::storage::DbSnapshot;
use crate::tendermint::abci::{Request as Req, Response as Resp, request};
use crate::tower_abci::BoxError;

/// The shim wraps the shell, which implements ABCI++.
/// The shim makes a crude translation between the ABCI interface currently used
/// by tendermint and the shell's interface.
#[derive(Debug)]
pub struct AbcippShim {
    service: Shell,
    shell_recv: std::sync::mpsc::Receiver<(
        Req,
        tokio::sync::oneshot::Sender<Result<Resp, BoxError>>,
    )>,
    snapshot_task: Option<std::thread::JoinHandle<Result<(), DbError>>>,
    snapshots_to_keep: u64,
    namada_version: String,
}

impl AbcippShim {
    /// Create a shell with a ABCI service that passes messages to and from the
    /// shell.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: config::Ledger,
        wasm_dir: PathBuf,
        broadcast_sender: UnboundedSender<Vec<u8>>,
        eth_oracle: Option<EthereumOracleChannels>,
        db_cache: &rocksdb::Cache,
        scheduled_migration: Option<ScheduledMigration>,
        vp_wasm_compilation_cache: u64,
        tx_wasm_compilation_cache: u64,
        namada_version: String,
    ) -> (Self, AbciService, broadcast::Sender<()>) {
        // We can use an unbounded channel here, because tower-abci limits the
        // the number of requests that can come in

        let (shell_send, shell_recv) = std::sync::mpsc::channel();
        let (server_shutdown, _) = broadcast::channel::<()>(1);
        let action_at_height = config.shell.action_at_height.clone();
        let snapshots_to_keep =
            config.shell.snapshots_to_keep.map(|n| n.get()).unwrap_or(1);
        (
            Self {
                service: Shell::new(
                    config,
                    wasm_dir,
                    broadcast_sender,
                    eth_oracle,
                    Some(db_cache),
                    scheduled_migration,
                    vp_wasm_compilation_cache,
                    tx_wasm_compilation_cache,
                ),
                shell_recv,
                snapshot_task: None,
                snapshots_to_keep,
                namada_version,
            },
            AbciService {
                shell_send,
                shutdown: server_shutdown.clone(),
                action_at_height,
                suspended: false,
            },
            server_shutdown,
        )
    }

    // /// Get the hash of the txs in the block
    // pub fn get_hash(&self) -> Hash {
    //     let bytes: Vec<u8> =
    //         self.delivered_txs.iter().flat_map(Clone::clone).collect();
    //     hash_tx(bytes.as_slice())
    // }

    /// Run the shell's blocking loop that receives messages from the
    /// [`AbciService`].
    pub fn run(mut self) {
        while let Ok((req, resp_sender)) = self.shell_recv.recv() {
            let resp = match req {
                Req::ProcessProposal(proposal) => self
                    .service
                    .call(
                        Request::ProcessProposal(proposal),
                        &self.namada_version,
                    )
                    .map_err(Error::from)
                    .and_then(|resp| resp.try_into()),
                Req::FinalizeBlock(mut request) => {
                    match self.get_process_proposal_result(request.clone()) {
                        ProcessProposalCachedResult::Accepted(tx_results) => {
                            let mut txs = Vec::with_capacity(tx_results.len());
                            for (result, tx) in tx_results.into_iter().zip(
                                std::mem::take(&mut request.txs).into_iter(),
                            ) {
                                txs.push(ProcessedTx {
                                    tx,
                                    result: result.into(),
                                });
                            }
                            let mut request: FinalizeBlock = request.into();
                            request.txs = txs;
                            self.service
                                .call(
                                    Request::FinalizeBlock(request),
                                    &self.namada_version,
                                )
                                .map_err(Error::from)
                                .and_then(|res| match res {
                                    Response::FinalizeBlock(resp) => {
                                        Ok(Resp::FinalizeBlock(resp.into()))
                                    }
                                    _ => Err(Error::ConvertResp(res)),
                                })
                        }
                        ProcessProposalCachedResult::Rejected => {
                            Err(Error::Shell(
                                crate::shell::Error::RejectedBlockProposal,
                            ))
                        }
                    }
                }
                Req::Commit => match self
                    .service
                    .call(Request::Commit, &self.namada_version)
                {
                    Ok(Response::Commit(res)) => {
                        let take_snapshot =
                            self.service.check_snapshot_required();
                        self.update_snapshot_task(take_snapshot);
                        Ok(Resp::Commit(res))
                    }
                    Ok(resp) => Err(Error::ConvertResp(resp)),
                    Err(e) => Err(Error::Shell(e)),
                },
                _ => match Request::try_from(req.clone()) {
                    Ok(request) => self
                        .service
                        .call(request, &self.namada_version)
                        .map(Resp::try_from)
                        .map_err(Error::Shell)
                        .and_then(|inner| inner),
                    Err(err) => Err(err),
                },
            };

            let resp = resp.map_err(|e| e.into());
            if resp_sender.send(resp).is_err() {
                tracing::info!("ABCI response channel is closed")
            }
        }
    }

    fn update_snapshot_task(&mut self, take_snapshot: TakeSnapshot) {
        let snapshot_taken =
            self.snapshot_task.as_ref().map(|t| t.is_finished());
        match snapshot_taken {
            Some(true) => {
                let task = self.snapshot_task.take().unwrap();
                match task.join() {
                    Ok(Err(e)) => tracing::error!(
                        "Failed to create snapshot with error: {:?}",
                        e
                    ),
                    Err(e) => tracing::error!(
                        "Failed to join thread creating snapshot: {:?}",
                        e
                    ),
                    _ => {}
                }
            }
            Some(false) => {
                // if a snapshot task is still running,
                // we don't start a new one. This is not
                // expected to happen if snapshots are spaced
                // far enough apart.
                tracing::warn!(
                    "Previous snapshot task was still running when a new \
                     snapshot was scheduled"
                );
                return;
            }
            _ => {}
        }

        let TakeSnapshot::Yes(db_path, height) = take_snapshot else {
            return;
        };
        // Ensure that the DB is flushed before making a checkpoint
        namada_sdk::state::DB::flush(self.service.state.db(), true).unwrap();
        let base_dir = self.service.base_dir.clone();

        let (snap_send, snap_recv) = tokio::sync::oneshot::channel();

        let snapshots_to_keep = self.snapshots_to_keep;
        let snapshot_task = std::thread::spawn(move || {
            let db = crate::storage::open(db_path, true, None)
                .expect("Could not open DB");
            let snapshot = db.checkpoint(base_dir.clone(), height)?;
            // signal to main thread that the snapshot has finished
            snap_send.send(()).unwrap();
            DbSnapshot::cleanup(height, &base_dir, snapshots_to_keep)
                .map_err(|e| DbError::DBError(e.to_string()))?;
            snapshot
                .package()
                .map_err(|e| DbError::DBError(e.to_string()))
        });

        // it's important that the thread is
        // blocked until the snapshot is created so that no writes
        // happen to the db while snapshotting. We want the db frozen
        // at this specific point in time.
        if snap_recv.blocking_recv().is_err() {
            tracing::error!("Failed to start snapshot task.")
        } else {
            self.snapshot_task.replace(snapshot_task);
        }
    }

    // Retrieve the cached result of process proposal for the given block or
    // compute it if missing
    fn get_process_proposal_result(
        &mut self,
        request: request::FinalizeBlock,
    ) -> ProcessProposalCachedResult {
        match namada_sdk::hash::Hash::try_from(request.hash) {
            Ok(block_hash) => {
                match self
                    .service
                    .state
                    .in_mem_mut()
                    .block_proposals_cache
                    .get(&block_hash)
                {
                    // We already have the result of process proposal for
                    // this block cached in memory
                    Some(res) => res.to_owned(),
                    None => {
                        // Need to run process proposal to extract the data we
                        // need for finalize block (tx results)
                        let process_req = CheckProcessProposal::from(request)
                            .cast_to_tendermint_req();

                        let (process_resp, res) =
                            self.service.process_proposal(process_req.into());
                        let result = if let ProcessProposal::Accept =
                            process_resp
                        {
                            ProcessProposalCachedResult::Accepted(
                                res.into_iter().map(|res| res.into()).collect(),
                            )
                        } else {
                            ProcessProposalCachedResult::Rejected
                        };

                        // Cache the result
                        self.service
                            .state
                            .in_mem_mut()
                            .block_proposals_cache
                            .put(block_hash.to_owned(), result.clone());

                        result
                    }
                }
            }
            Err(_) => {
                // Need to run process proposal to extract the data we need for
                // finalize block (tx results)
                let process_req = CheckProcessProposal::from(request)
                    .cast_to_tendermint_req();

                // Do not cache the result in this case since we
                // don't have the hash of the block
                let (process_resp, res) =
                    self.service.process_proposal(process_req.into());
                if let ProcessProposal::Accept = process_resp {
                    ProcessProposalCachedResult::Accepted(
                        res.into_iter().map(|res| res.into()).collect(),
                    )
                } else {
                    ProcessProposalCachedResult::Rejected
                }
            }
        }
    }
}

/// Indicates how [`AbciService`] should
/// check whether or not it needs to take
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

#[derive(Debug)]
pub struct AbciService {
    /// A channel for forwarding requests to the shell
    shell_send: std::sync::mpsc::Sender<(
        Req,
        tokio::sync::oneshot::Sender<Result<Resp, BoxError>>,
    )>,
    /// Indicates if the consensus connection is suspended.
    suspended: bool,
    /// This resolves the non-completing futures returned to tower-abci
    /// during suspension.
    shutdown: broadcast::Sender<()>,
    /// An action to be taken at a specified block height.
    action_at_height: Option<ActionAtHeight>,
}

impl AbciService {
    /// Check if we are at a block height with a scheduled action.
    /// If so, perform the action.
    fn maybe_take_action(
        action_at_height: Option<ActionAtHeight>,
        check: CheckAction,
        mut shutdown_recv: broadcast::Receiver<()>,
    ) -> (bool, Option<<Self as Service<Req>>::Future>) {
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

    /// If we are not taking special action for this request,
    /// forward it normally.
    fn forward_request(&mut self, req: Req) -> <Self as Service<Req>>::Future {
        let (resp_send, recv) = tokio::sync::oneshot::channel();
        let result = self.shell_send.send((req.clone(), resp_send));
        async move {
            let genesis_time = if let Req::InitChain(init) = req {
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
impl Service<Req> for AbciService {
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
