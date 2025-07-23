use std::fmt::{Debug, Formatter};
use std::future::poll_fn;
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use color_eyre::eyre::{Report, Result};
use data_encoding::HEXUPPER;
use itertools::Either;
use lazy_static::lazy_static;
use namada_sdk::address::Address;
use namada_sdk::chain::{BlockHeader, BlockHeight, Epoch};
use namada_sdk::collections::HashMap;
use namada_sdk::control_flow::time::Duration;
use namada_sdk::eth_bridge::oracle::config::Config as OracleConfig;
use namada_sdk::ethereum_events::EthereumEvent;
use namada_sdk::events::Event;
use namada_sdk::events::extend::Height as HeightAttr;
use namada_sdk::events::log::dumb_queries;
use namada_sdk::hash::Hash;
use namada_sdk::io::Client;
use namada_sdk::key::tm_consensus_key_raw_hash;
use namada_sdk::proof_of_stake::storage::{
    read_consensus_validator_set_addresses_with_stake, read_pos_params,
    validator_consensus_key_handle,
};
use namada_sdk::proof_of_stake::types::WeightedValidator;
use namada_sdk::queries::{
    EncodedResponseQuery, RPC, RequestCtx, RequestQuery, Router,
};
use namada_sdk::state::{
    DBRead, EPOCH_SWITCH_BLOCKS_DELAY, LastBlock, Sha256Hasher, StorageRead,
};
use namada_sdk::tendermint::abci::response::Info;
use namada_sdk::tendermint::abci::types::VoteInfo;
use namada_sdk::tendermint_proto::google::protobuf::Timestamp;
use namada_sdk::time::DateTimeUtc;
use namada_sdk::tx::data::ResultCode;
use namada_sdk::tx::event::{Batch as BatchAttr, Code as CodeAttr};
use namada_sdk::{borsh, ethereum_structs, governance};
use regex::Regex;
use tokio::sync::mpsc;

use crate::ethereum_oracle::test_tools::mock_web3_client::{
    TestOracle, Web3Client, Web3Controller,
};
use crate::ethereum_oracle::{
    control, last_processed_block, try_process_eth_events,
};
use crate::shell::testing::utils::TestDir;
use crate::shell::token::MaspEpoch;
use crate::shell::{EthereumOracleChannels, Shell};
use crate::shims::abcipp_shim_types::shim::request::{
    FinalizeBlock, ProcessedTx,
};
use crate::shims::abcipp_shim_types::shim::response::TxResult;
use crate::tendermint_proto::abci::{
    RequestPrepareProposal, RequestProcessProposal,
};
use crate::tendermint_rpc::SimpleRequest;
use crate::tendermint_rpc::endpoint::block;
use crate::tendermint_rpc::error::Error as RpcError;
use crate::{dry_run_tx, storage, tendermint, tendermint_rpc};

/// Mock Ethereum oracle used for testing purposes.
struct MockEthOracle {
    /// The inner oracle.
    oracle: TestOracle,
    /// The inner oracle's configuration.
    config: OracleConfig,
    /// The inner oracle's next block to process.
    next_block_to_process: tokio::sync::RwLock<ethereum_structs::BlockHeight>,
}

impl MockEthOracle {
    /// Updates the state of the Ethereum oracle.
    ///
    /// This includes sending any confirmed Ethereum events to
    /// the shell and updating the height of the next Ethereum
    /// block to process. Upon a successfully processed block,
    /// this functions returns `true`.
    async fn drive(&self) -> bool {
        try_process_eth_events(
            &self.oracle,
            &self.config,
            &*self.next_block_to_process.read().await,
        )
        .await
        .process_new_block()
    }
}

/// Services mocking the operation of the ledger's various async tasks.
pub struct MockServices {
    /// Receives transactions that are supposed to be broadcasted
    /// to the network.
    tx_receiver: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Mock Ethereum oracle, that processes blocks from Ethereum
    /// in order to find events emitted by a transaction to vote on.
    ethereum_oracle: MockEthOracle,
}

/// Actions to be performed by the mock node, as a result
/// of driving [`MockServices`].
pub enum MockServiceAction {
    /// The ledger should broadcast new transactions.
    BroadcastTxs(Vec<Vec<u8>>),
    /// Progress to the next Ethereum block to process.
    IncrementEthHeight,
}

impl MockServices {
    /// Drive the internal state machine of the mock node's services.
    async fn drive(&self) -> Vec<MockServiceAction> {
        let mut actions = vec![];

        // process new eth events
        // NOTE: this may result in a deadlock, if the events
        // sent to the shell exceed the capacity of the oracle's
        // events channel!
        if self.ethereum_oracle.drive().await {
            actions.push(MockServiceAction::IncrementEthHeight);
        }

        // receive txs from the broadcaster
        let txs = {
            let mut txs = vec![];
            let mut tx_receiver = self.tx_receiver.lock().await;

            while let Some(tx) = poll_fn(|cx| match tx_receiver.poll_recv(cx) {
                Poll::Pending => Poll::Ready(None),
                poll => poll,
            })
            .await
            {
                txs.push(tx);
            }

            txs
        };
        if !txs.is_empty() {
            actions.push(MockServiceAction::BroadcastTxs(txs));
        }

        actions
    }
}

/// Controller of various mock node services.
pub struct MockServicesController {
    /// Ethereum oracle controller.
    pub eth_oracle: Web3Controller,
    /// Handler to the Ethereum oracle sender channel.
    ///
    /// Bypasses the Ethereum oracle service and sends
    /// events directly to the [`Shell`].
    pub eth_events: mpsc::Sender<EthereumEvent>,
    /// Transaction broadcaster handle.
    pub tx_broadcaster: mpsc::UnboundedSender<Vec<u8>>,
}

/// Service handlers to be passed to a [`Shell`], when building
/// a mock node.
pub struct MockServiceShellHandlers {
    /// Transaction broadcaster handle.
    pub tx_broadcaster: mpsc::UnboundedSender<Vec<u8>>,
    /// Ethereum oracle channel handlers.
    pub eth_oracle_channels: Option<EthereumOracleChannels>,
}

/// Mock services data returned by [`mock_services`].
pub struct MockServicesPackage {
    /// Whether to automatically drive mock services or not.
    pub auto_drive_services: bool,
    /// Mock services stored by the [`MockNode`].
    pub services: MockServices,
    /// Handlers to mock services stored by the [`Shell`].
    pub shell_handlers: MockServiceShellHandlers,
    /// Handler to the mock services controller.
    pub controller: MockServicesController,
}

/// Mock services config.
pub struct MockServicesCfg {
    /// Whether to automatically drive mock services or not.
    pub auto_drive_services: bool,
    /// Whether to enable the Ethereum oracle or not.
    pub enable_eth_oracle: bool,
}

/// Instantiate mock services for a node.
pub fn mock_services(cfg: MockServicesCfg) -> MockServicesPackage {
    let (_, eth_client) = Web3Client::setup();
    let (eth_sender, eth_receiver) = mpsc::channel(1000);
    let (last_processed_block_sender, last_processed_block_receiver) =
        last_processed_block::channel();
    let (control_sender, control_receiver) = control::channel();
    let eth_oracle_controller = eth_client.controller();
    let oracle = TestOracle::new(
        Either::Left(eth_client),
        eth_sender.clone(),
        last_processed_block_sender,
        Duration::from_millis(5),
        Duration::from_secs(30),
        control_receiver,
    );
    let eth_oracle_channels = EthereumOracleChannels::new(
        eth_receiver,
        control_sender,
        last_processed_block_receiver,
    );
    let (tx_broadcaster, tx_receiver) = mpsc::unbounded_channel();
    let ethereum_oracle = MockEthOracle {
        oracle,
        config: Default::default(),
        next_block_to_process: tokio::sync::RwLock::new(Default::default()),
    };
    MockServicesPackage {
        auto_drive_services: cfg.auto_drive_services,
        services: MockServices {
            ethereum_oracle,
            tx_receiver: tokio::sync::Mutex::new(tx_receiver),
        },
        shell_handlers: MockServiceShellHandlers {
            tx_broadcaster: tx_broadcaster.clone(),
            eth_oracle_channels: cfg
                .enable_eth_oracle
                .then_some(eth_oracle_channels),
        },
        controller: MockServicesController {
            eth_oracle: eth_oracle_controller,
            eth_events: eth_sender,
            tx_broadcaster,
        },
    }
}

/// Status of tx
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeResults {
    /// Success
    Ok,
    /// Rejected by Process Proposal
    Rejected(TxResult),
    /// Failure in application in Finalize Block
    Failed(ResultCode),
}

pub struct InnerMockNode {
    pub shell: Mutex<Shell<storage::PersistentDB, Sha256Hasher>>,
    pub test_dir: SalvageableTestDir,
    pub tx_result_codes: Mutex<Vec<NodeResults>>,
    pub tx_results: Mutex<Vec<namada_sdk::tx::data::TxResult<String>>>,
    pub blocks: Mutex<HashMap<BlockHeight, block::Response>>,
    pub services: MockServices,
    pub auto_drive_services: bool,
}

#[derive(Clone)]
pub struct MockNode(pub Arc<InnerMockNode>);

impl Deref for MockNode {
    type Target = InnerMockNode;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct SalvageableTestDir {
    pub test_dir: ManuallyDrop<TestDir>,
    pub keep_temp: bool,
}

impl Deref for SalvageableTestDir {
    type Target = TestDir;

    fn deref(&self) -> &Self::Target {
        &self.test_dir
    }
}

impl Debug for MockNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockNode")
            .field("shell", &self.shell)
            .finish()
    }
}

impl Drop for SalvageableTestDir {
    fn drop(&mut self) {
        unsafe {
            if !self.keep_temp {
                ManuallyDrop::take(&mut self.test_dir).clean_up()
            } else {
                println!(
                    "Keeping tempfile at {}",
                    self.test_dir.path().to_string_lossy()
                );
                ManuallyDrop::drop(&mut self.test_dir)
            }
        }
    }
}

impl MockNode {
    pub async fn handle_service_action(&self, action: MockServiceAction) {
        match action {
            MockServiceAction::BroadcastTxs(txs) => {
                self.submit_txs(txs);
            }
            MockServiceAction::IncrementEthHeight => {
                let mut height = self
                    .services
                    .ethereum_oracle
                    .next_block_to_process
                    .write()
                    .await;
                *height = height.next();
            }
        }
    }

    pub async fn drive_mock_services(&self) {
        for action in self.services.drive().await {
            self.handle_service_action(action).await;
        }
    }

    async fn drive_mock_services_bg(&self) {
        if self.auto_drive_services {
            self.drive_mock_services().await;
        }
    }

    pub fn genesis_dir(&self) -> PathBuf {
        self.test_dir
            .path()
            .join(self.shell.lock().unwrap().chain_id.to_string())
    }

    pub fn genesis_path(&self) -> PathBuf {
        self.test_dir
            .path()
            .join(format!("{}.toml", self.shell.lock().unwrap().chain_id))
    }

    pub fn wasm_dir(&self) -> PathBuf {
        self.genesis_path().join("wasm")
    }

    pub fn wallet_path(&self) -> PathBuf {
        self.genesis_dir().join("wallet.toml")
    }

    pub fn db_path(&self) -> PathBuf {
        let locked = self.shell.lock().unwrap();
        locked.state.db().path().unwrap().to_path_buf()
    }

    pub fn block_height(&self) -> BlockHeight {
        #[allow(clippy::disallowed_methods)]
        self.shell
            .lock()
            .unwrap()
            .state
            .get_block_height()
            .unwrap_or_default()
    }

    pub fn current_epoch(&self) -> Epoch {
        self.shell.lock().unwrap().state.in_mem().last_epoch
    }

    pub fn next_epoch(&mut self) -> Epoch {
        #[allow(clippy::disallowed_methods)]
        let header_time = DateTimeUtc::now();
        {
            let mut locked = self.shell.lock().unwrap();

            let next_epoch_height =
                locked.state.in_mem().get_last_block_height() + 1;
            locked.state.in_mem_mut().next_epoch_min_start_height =
                next_epoch_height;
            locked.state.in_mem_mut().next_epoch_min_start_time = header_time;
            if let Some(LastBlock { height, .. }) =
                locked.state.in_mem_mut().last_block.as_mut()
            {
                *height = next_epoch_height;
            }
        }
        // Use the same timestamp as `next_epoch_min_start_time` to ensure a new
        // epoch is started on this block
        self.finalize_and_commit(Some(header_time));

        for _ in 0..EPOCH_SWITCH_BLOCKS_DELAY {
            self.finalize_and_commit(None);
        }
        self.shell
            .lock()
            .unwrap()
            .state
            .in_mem()
            .get_current_epoch()
            .0
    }

    pub fn current_masp_epoch(&mut self) -> MaspEpoch {
        let masp_epoch_multiplier =
            namada_sdk::parameters::read_masp_epoch_multiplier_parameter(
                &self.shell.lock().unwrap().state,
            )
            .unwrap();
        let current_epoch = self.current_epoch();
        MaspEpoch::try_from_epoch(current_epoch, masp_epoch_multiplier).unwrap()
    }

    pub fn next_masp_epoch(&mut self) -> Epoch {
        let masp_epoch_multiplier =
            namada_sdk::parameters::read_masp_epoch_multiplier_parameter(
                &self.shell.lock().unwrap().state,
            )
            .unwrap();
        let mut epoch = Epoch::default();

        for _ in 0..masp_epoch_multiplier {
            epoch = self.next_epoch();
        }

        epoch
    }

    pub fn native_token(&self) -> Address {
        let locked = self.shell.lock().unwrap();
        locked.state.get_native_token().unwrap()
    }

    /// Get the address of the block proposer and the votes for the block
    fn prepare_request(&self) -> (Vec<u8>, Vec<VoteInfo>) {
        let (val1, ck) = {
            let locked = self.shell.lock().unwrap();
            let params =
                read_pos_params::<_, governance::Store<_>>(&locked.state)
                    .unwrap();
            let current_epoch = locked.state.in_mem().get_current_epoch().0;
            let consensus_set: Vec<WeightedValidator> =
                read_consensus_validator_set_addresses_with_stake(
                    &locked.state,
                    current_epoch,
                )
                .unwrap()
                .into_iter()
                .collect();

            let val1 = consensus_set[0].clone();
            let ck = validator_consensus_key_handle(&val1.address)
                .get(&locked.state, current_epoch, &params)
                .unwrap()
                .unwrap();
            (val1, ck)
        };

        let hash_string = tm_consensus_key_raw_hash(&ck);
        let pkh1 = HEXUPPER.decode(hash_string.as_bytes()).unwrap();
        let votes = vec![VoteInfo {
            validator: tendermint::abci::types::Validator {
                address: pkh1.clone().try_into().unwrap(),
                power: (u128::try_from(val1.bonded_stake).expect("Test failed")
                    as u64)
                    .try_into()
                    .unwrap(),
            },
            sig_info: tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];

        (pkh1, votes)
    }

    /// Simultaneously call the `FinalizeBlock` and
    /// `Commit` handlers.
    pub fn finalize_and_commit(&self, header_time: Option<DateTimeUtc>) {
        let (proposer_address, votes) = self.prepare_request();

        let mut locked = self.shell.lock().unwrap();
        let height =
            locked.state.in_mem().get_last_block_height().next_height();

        // check if we have protocol txs to be included
        // in the finalize block request
        let txs: Vec<ProcessedTx> = {
            let req = RequestPrepareProposal {
                proposer_address: proposer_address.clone().into(),
                ..Default::default()
            };
            let txs = locked.prepare_proposal(req).txs;

            txs.into_iter()
                .map(|tx| ProcessedTx {
                    tx,
                    result: TxResult {
                        code: 0,
                        info: String::new(),
                    },
                })
                .collect()
        };
        // build finalize block abci request
        let req = FinalizeBlock {
            header: BlockHeader {
                hash: Hash([0; 32]),
                #[allow(clippy::disallowed_methods)]
                time: header_time.unwrap_or_else(DateTimeUtc::now),
                next_validators_hash: Hash([0; 32]),
            },
            block_hash: Hash([0; 32]),
            byzantine_validators: vec![],
            txs: txs.clone(),
            proposer_address,
            height: height.try_into().unwrap(),
            decided_last_commit: tendermint::abci::types::CommitInfo {
                round: 0u8.into(),
                votes,
            },
        };

        let resp = locked.finalize_block(req).expect("Test failed");
        let mut result_codes = resp
            .events
            .iter()
            .filter_map(|e| {
                e.read_attribute_opt::<CodeAttr>()
                    .unwrap()
                    .map(|result_code| {
                        if result_code == ResultCode::Ok {
                            NodeResults::Ok
                        } else {
                            NodeResults::Failed(result_code)
                        }
                    })
            })
            .collect::<Vec<_>>();
        let mut tx_results = resp
            .events
            .into_iter()
            .filter_map(|e| e.read_attribute_opt::<BatchAttr<'_>>().unwrap())
            .collect::<Vec<_>>();
        self.tx_result_codes
            .lock()
            .unwrap()
            .append(&mut result_codes);
        self.tx_results.lock().unwrap().append(&mut tx_results);
        locked.commit();

        // Cache the block
        self.blocks.lock().unwrap().insert(
            height,
            block::Response {
                block_id: tendermint::block::Id {
                    hash: tendermint::Hash::None,
                    part_set_header: tendermint::block::parts::Header::default(
                    ),
                },
                block: tendermint::block::Block::new(
                    tendermint::block::Header {
                        version: tendermint::block::header::Version {
                            block: 0,
                            app: 0,
                        },
                        chain_id: locked
                            .chain_id
                            .to_string()
                            .try_into()
                            .unwrap(),
                        height: 1u32.into(),
                        time: tendermint::Time::now(),
                        last_block_id: None,
                        last_commit_hash: None,
                        data_hash: None,
                        validators_hash: tendermint::Hash::None,
                        next_validators_hash: tendermint::Hash::None,
                        consensus_hash: tendermint::Hash::None,
                        app_hash: tendermint::AppHash::default(),
                        last_results_hash: None,
                        evidence_hash: None,
                        proposer_address: tendermint::account::Id::new(
                            [0u8; 20],
                        ),
                    },
                    txs.into_iter().map(|tx| tx.tx.to_vec()).collect(),
                    tendermint::evidence::List::default(),
                    None,
                ),
            },
        );
    }

    /// Send a tx through Process Proposal and Finalize Block
    /// and register the results.
    pub fn submit_txs(&self, txs: Vec<Vec<u8>>) {
        self.finalize_and_commit(None);
        let (proposer_address, votes) = self.prepare_request();

        #[allow(clippy::disallowed_methods)]
        let time = DateTimeUtc::now();
        let req = RequestProcessProposal {
            txs: txs.clone().into_iter().map(|tx| tx.into()).collect(),
            proposer_address: proposer_address.clone().into(),
            time: Some(Timestamp {
                seconds: time.0.timestamp(),
                nanos: time.0.timestamp_subsec_nanos() as i32,
            }),
            ..Default::default()
        };
        let mut locked = self.shell.lock().unwrap();
        let height =
            locked.state.in_mem().get_last_block_height().next_height();
        let (result, tx_results) = locked.process_proposal(req);

        let mut errors: Vec<_> = tx_results
            .iter()
            .map(|e| {
                if e.code == 0 {
                    NodeResults::Ok
                } else {
                    NodeResults::Rejected(e.clone())
                }
            })
            .collect();
        if result != tendermint::abci::response::ProcessProposal::Accept {
            self.tx_result_codes.lock().unwrap().append(&mut errors);
            return;
        }

        // process proposal succeeded, now run finalize block

        let time = {
            #[allow(clippy::disallowed_methods)]
            let time = DateTimeUtc::now();
            // Set the block time in the past to avoid non-deterministically
            // starting new epochs
            let dur = namada_sdk::time::Duration::minutes(10);
            time - dur
        };
        let req = FinalizeBlock {
            header: BlockHeader {
                hash: Hash([0; 32]),
                #[allow(clippy::disallowed_methods)]
                time,
                next_validators_hash: Hash([0; 32]),
            },
            block_hash: Hash([0; 32]),
            byzantine_validators: vec![],
            txs: txs
                .clone()
                .into_iter()
                .zip(tx_results)
                .map(|(tx, result)| ProcessedTx {
                    tx: tx.into(),
                    result,
                })
                .collect(),
            proposer_address,
            height: height.try_into().unwrap(),
            decided_last_commit: tendermint::abci::types::CommitInfo {
                round: 0u8.into(),
                votes,
            },
        };

        // process the results
        let resp = locked.finalize_block(req).unwrap();
        let mut error_codes = resp
            .events
            .iter()
            .filter_map(|e| {
                e.read_attribute_opt::<CodeAttr>()
                    .unwrap()
                    .map(|result_code| {
                        if result_code == ResultCode::Ok {
                            NodeResults::Ok
                        } else {
                            NodeResults::Failed(result_code)
                        }
                    })
            })
            .collect::<Vec<_>>();
        let mut txs_results = resp
            .events
            .into_iter()
            .filter_map(|e| e.read_attribute_opt::<BatchAttr<'_>>().unwrap())
            .collect::<Vec<_>>();
        self.tx_result_codes
            .lock()
            .unwrap()
            .append(&mut error_codes);
        self.tx_results.lock().unwrap().append(&mut txs_results);
        self.blocks.lock().unwrap().insert(
            height,
            block::Response {
                block_id: tendermint::block::Id {
                    hash: tendermint::Hash::None,
                    part_set_header: tendermint::block::parts::Header::default(
                    ),
                },
                block: tendermint::block::Block::new(
                    tendermint::block::Header {
                        version: tendermint::block::header::Version {
                            block: 0,
                            app: 0,
                        },
                        chain_id: locked
                            .chain_id
                            .to_string()
                            .try_into()
                            .unwrap(),
                        height: 1u32.into(),
                        time: tendermint::Time::now(),
                        last_block_id: None,
                        last_commit_hash: None,
                        data_hash: None,
                        validators_hash: tendermint::Hash::None,
                        next_validators_hash: tendermint::Hash::None,
                        consensus_hash: tendermint::Hash::None,
                        app_hash: tendermint::AppHash::default(),
                        last_results_hash: None,
                        evidence_hash: None,
                        proposer_address: tendermint::account::Id::new(
                            [0u8; 20],
                        ),
                    },
                    txs,
                    tendermint::evidence::List::default(),
                    None,
                ),
            },
        );
        locked.commit();
    }

    // Check that applying a tx succeeded.
    fn success(&self) -> bool {
        let tx_result_codes = self.tx_result_codes.lock().unwrap();
        let tx_results = self.tx_results.lock().unwrap();

        // If results are empty return false to avoid silently ignoring missing
        // results
        !tx_result_codes.is_empty()
            && !tx_results.is_empty()
            && tx_result_codes.iter().all(|r| *r == NodeResults::Ok)
            && tx_results
                .iter()
                .all(|inner_results| inner_results.are_results_successfull())
    }

    // Return a tx result if the tx failed in mempool
    fn is_broadcast_err(&self) -> Option<TxResult> {
        self.tx_result_codes
            .lock()
            .unwrap()
            .iter()
            .find_map(|r| match r {
                NodeResults::Ok | NodeResults::Failed(_) => None,
                NodeResults::Rejected(tx_result) => Some(tx_result.clone()),
            })
    }

    pub fn clear_results(&self) {
        self.tx_result_codes.lock().unwrap().clear();
        self.tx_results.lock().unwrap().clear();
    }

    /// WARNING: use this function only if you went through one of the methods
    /// of `MockNode` to execute your tx (such as finalize_and_commit). If you
    /// just submitted a tx using the Client command avoid calling this function
    /// (which would return false since the support fields of MockNode would not
    /// be populated or would be populated with stale data) and rely instead on
    /// examining the captured output of your command.
    pub fn assert_success(&self) {
        if !self.success() {
            panic!(
                "Assert failed: The node did not execute \
                 successfully:\nErrors:\n    {:?},\nTxs results:\n    {:?}",
                self.tx_result_codes.lock().unwrap(),
                self.tx_results.lock().unwrap()
            );
        }
        self.clear_results();
    }
}

#[async_trait::async_trait(?Send)]
impl Client for MockNode {
    type Error = Report;

    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> std::result::Result<EncodedResponseQuery, Report> {
        self.drive_mock_services_bg().await;
        let rpc = RPC;
        let data = data.unwrap_or_default();
        let latest_height = {
            self.shell
                .lock()
                .unwrap()
                .state
                .in_mem()
                .last_block
                .as_ref()
                .map(|b| b.height)
                .unwrap_or_default()
        };
        let height = height.unwrap_or(latest_height);
        // Handle a path by invoking the `RPC.handle` directly with the
        // borrowed storage
        let request = RequestQuery {
            data: data.into(),
            path,
            height: height.try_into().unwrap(),
            prove,
        };
        let borrowed = self.shell.lock().unwrap();
        if request.path == RPC.shell().dry_run_tx_path() {
            dry_run_tx(
                // This is safe because nothing else is using `self.state`
                // concurrently and the `TempWlState` will be dropped right
                // after dry-run.
                unsafe { borrowed.state.with_static_temp_write_log() },
                borrowed.vp_wasm_cache.read_only(),
                borrowed.tx_wasm_cache.read_only(),
                &request,
            )
        } else {
            let ctx = RequestCtx {
                state: &borrowed.state,
                event_log: borrowed.event_log(),
                vp_wasm_cache: borrowed.vp_wasm_cache.read_only(),
                tx_wasm_cache: borrowed.tx_wasm_cache.read_only(),
                storage_read_past_height_limit: None,
            };
            rpc.handle(ctx, &request)
        }
        .map_err(Report::new)
    }

    async fn perform<R>(
        &self,
        _request: R,
    ) -> std::result::Result<R::Output, RpcError>
    where
        R: SimpleRequest,
    {
        unimplemented!("Client's perform method is not implemented for testing")
    }

    /// `/abci_info`: get information about the ABCI application.
    async fn abci_info(&self) -> Result<Info, RpcError> {
        self.drive_mock_services_bg().await;
        let locked = self.shell.lock().unwrap();
        Ok(Info {
            data: "Namada".to_string(),
            version: "test".to_string(),
            app_version: 0,
            last_block_height: locked
                .state
                .in_mem()
                .last_block
                .as_ref()
                .map(|b| b.height.0 as u32)
                .unwrap_or_default()
                .into(),
            last_block_app_hash: tendermint::AppHash::default(),
        })
    }

    /// `/broadcast_tx_sync`: broadcast a transaction, returning the response
    /// from `CheckTx`.
    async fn broadcast_tx_sync(
        &self,
        tx: impl Into<Vec<u8>>,
    ) -> Result<tendermint_rpc::endpoint::broadcast::tx_sync::Response, RpcError>
    {
        self.drive_mock_services_bg().await;
        let mut resp = tendermint_rpc::endpoint::broadcast::tx_sync::Response {
            codespace: Default::default(),
            code: Default::default(),
            data: Default::default(),
            log: Default::default(),
            hash: tendermint::Hash::default(),
        };
        let tx_bytes: Vec<u8> = tx.into();
        self.submit_txs(vec![tx_bytes]);

        // If the error happened during broadcasting, attach its result to
        // response
        if let Some(TxResult { code, info }) = self.is_broadcast_err() {
            resp.code = code.into();
            resp.log = info;
        }

        self.clear_results();
        Ok(resp)
    }

    /// `/block_search`: search for blocks by BeginBlock and EndBlock events.
    async fn block_search(
        &self,
        query: namada_sdk::tendermint_rpc::query::Query,
        _page: u32,
        _per_page: u8,
        _order: namada_sdk::tendermint_rpc::Order,
    ) -> Result<tendermint_rpc::endpoint::block_search::Response, RpcError>
    {
        self.drive_mock_services_bg().await;
        let matcher = parse_tm_query(query);
        let borrowed = self.shell.lock().unwrap();

        // we store a hash of some event in the log as a block
        // height in the response of the query... VERY NAISSSE
        let matching_events = borrowed.event_log().iter().flat_map(|event| {
            if matcher.matches(event) {
                Some(EncodedEvent::encode(event))
            } else {
                None
            }
        });
        let blocks = matching_events
            .map(block_search_response)
            .collect::<Vec<_>>();

        Ok(
            namada_sdk::tendermint_rpc::endpoint::block_search::Response {
                total_count: blocks.len() as u32,
                blocks,
            },
        )
    }

    /// `/block_results`: get ABCI results for a block at a particular height.
    async fn block_results<H>(
        &self,
        height: H,
    ) -> Result<tendermint_rpc::endpoint::block_results::Response, RpcError>
    where
        H: TryInto<namada_sdk::tendermint::block::Height> + Send,
    {
        self.drive_mock_services_bg().await;
        let height = height.try_into().map_err(|_| {
            RpcError::parse("Failed to cast block height".to_string())
        })?;
        let locked = self.shell.lock().unwrap();
        let events: Vec<_> = locked
            .event_log()
            .iter()
            .flat_map(|event| {
                let same_block_height = event
                    .read_attribute::<HeightAttr>()
                    .map(|event_height| {
                        BlockHeight(height.value()) == event_height
                    })
                    .unwrap_or(false);
                let same_encoded_event =
                    EncodedEvent::encode(event) == EncodedEvent(height.value());

                if same_block_height || same_encoded_event {
                    Some(event)
                } else {
                    None
                }
            })
            .map(|event| {
                namada_sdk::tendermint::abci::Event::from(event.clone())
            })
            .collect();
        let has_events = !events.is_empty();
        Ok(tendermint_rpc::endpoint::block_results::Response {
            height,
            txs_results: None,
            finalize_block_events: vec![],
            begin_block_events: None,
            end_block_events: has_events.then_some(events),
            validator_updates: vec![],
            consensus_param_updates: None,
            app_hash: namada_sdk::tendermint::hash::AppHash::default(),
        })
    }

    async fn block<H>(
        &self,
        height: H,
    ) -> Result<tendermint_rpc::endpoint::block::Response, RpcError>
    where
        H: TryInto<tendermint::block::Height> + Send,
    {
        // NOTE: atm this is only needed to query blocks at a
        // specific height for masp transactions
        let height = BlockHeight(
            height
                .try_into()
                .map_err(|_| {
                    RpcError::parse("Failed to cast block height".to_string())
                })?
                .into(),
        );

        self.blocks
            .lock()
            .unwrap()
            .get(&height)
            .cloned()
            .ok_or_else(|| {
                RpcError::invalid_params(format!(
                    "Could not find block at height {height}"
                ))
            })
    }

    /// `/tx_search`: search for transactions with their results.
    async fn tx_search(
        &self,
        _query: namada_sdk::tendermint_rpc::query::Query,
        _prove: bool,
        _page: u32,
        _per_page: u8,
        _order: namada_sdk::tendermint_rpc::Order,
    ) -> Result<tendermint_rpc::endpoint::tx_search::Response, RpcError> {
        // In the past, some cli commands for masp called this. However, these
        // commands are not currently supported, so we do not need to fill
        // in this function for now.
        unreachable!()
    }

    /// `/health`: get node health.
    ///
    /// Returns empty result (200 OK) on success, no response in case of an
    /// error.
    async fn health(&self) -> Result<(), RpcError> {
        self.drive_mock_services_bg().await;
        Ok(())
    }
}

/// Parse a Tendermint query.
fn parse_tm_query(
    query: namada_sdk::tendermint_rpc::query::Query,
) -> dumb_queries::QueryMatcher {
    const QUERY_PARSING_REGEX_STR: &str =
        r"^tm\.event='NewBlock' AND applied\.hash='([^']+)'$";

    lazy_static! {
        /// Compiled regular expression used to parse Tendermint queries.
        static ref QUERY_PARSING_REGEX: Regex = Regex::new(QUERY_PARSING_REGEX_STR).unwrap();
    }

    let query = query.to_string();
    let captures = QUERY_PARSING_REGEX.captures(&query).unwrap();

    match captures.get(0).unwrap().as_str() {
        "applied" => dumb_queries::QueryMatcher::applied(
            captures.get(1).unwrap().as_str().try_into().unwrap(),
        ),
        _ => unreachable!("We only query applied txs"),
    }
}

/// A Namada event hash encoded as a Tendermint block height.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
struct EncodedEvent(u64);

impl EncodedEvent {
    /// Encode an event.
    fn encode(event: &Event) -> Self {
        use std::hash::{DefaultHasher, Hasher};

        let mut hasher = DefaultHasher::default();
        borsh::to_writer(HasherWriter(&mut hasher), event).unwrap();

        Self(hasher.finish())
    }
}

/// Hasher that implements [`std::io::Write`].
struct HasherWriter<H>(H);

impl<H> std::io::Write for HasherWriter<H>
where
    H: std::hash::Hasher,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::hash::Hasher::write(&mut self.0, buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[inline]
fn block_search_response(
    encoded_event: EncodedEvent,
) -> namada_sdk::tendermint_rpc::endpoint::block::Response {
    namada_sdk::tendermint_rpc::endpoint::block::Response {
        block_id: Default::default(),
        block: namada_sdk::tendermint_proto::types::Block {
            header: Some(namada_sdk::tendermint_proto::types::Header {
                version: Some(
                    namada_sdk::tendermint_proto::version::Consensus {
                        block: 0,
                        app: 0,
                    },
                ),
                chain_id: String::new(),
                // NB: this is the only field that matters to us,
                // everything else is junk
                height: encoded_event.0 as i64,
                time: None,
                last_block_id: None,
                last_commit_hash: vec![],
                data_hash: vec![],
                validators_hash: vec![],
                next_validators_hash: vec![],
                consensus_hash: vec![],
                app_hash: vec![],
                last_results_hash: vec![],
                evidence_hash: vec![],
                proposer_address: vec![],
            }),
            data: Default::default(),
            evidence: Default::default(),
            last_commit: Some(namada_sdk::tendermint_proto::types::Commit {
                height: encoded_event.0 as i64,
                round: 0,
                block_id: Some(namada_sdk::tendermint_proto::types::BlockId {
                    hash: vec![0u8; 32],
                    part_set_header: Some(
                        namada_sdk::tendermint_proto::types::PartSetHeader {
                            total: 1,
                            hash: vec![1; 32],
                        },
                    ),
                }),
                signatures: vec![],
            }),
        }
        .try_into()
        .unwrap(),
    }
}
