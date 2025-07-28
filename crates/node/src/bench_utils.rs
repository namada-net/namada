//! Library code for benchmarks provides a wrapper of the ledger's shell
//! `BenchShell` and helper functions to generate transactions.

#![allow(clippy::arithmetic_side_effects)]

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

use either::Either;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::Transaction;
use masp_primitives::transaction::components::sapling::builder::RngBuildParams;
use masp_primitives::zip32::ExtendedFullViewingKey;
use masp_proofs::prover::LocalTxProver;
use namada_apps_lib::cli;
use namada_apps_lib::cli::Context;
use namada_apps_lib::cli::context::FromContext;
use namada_apps_lib::key::SchemeType;
use namada_apps_lib::wallet::{CliWalletUtils, defaults};
use namada_sdk::address::{self, Address, InternalAddress, MASP};
use namada_sdk::args::ShieldedSync;
use namada_sdk::borsh::{
    self, BorshDeserialize, BorshSerialize, BorshSerializeExt,
};
use namada_sdk::chain::testing::get_dummy_header;
use namada_sdk::chain::{BlockHeight, ChainId, Epoch};
use namada_sdk::events::Event;
use namada_sdk::events::extend::{ComposeEvent, InnerTxHash, TxHash};
use namada_sdk::gas::TxGasMeter;
use namada_sdk::governance::storage::proposal::ProposalType;
use namada_sdk::governance::{self, InitProposalData};
use namada_sdk::ibc::apps::transfer::types::PrefixedCoin;
use namada_sdk::ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use namada_sdk::ibc::apps::transfer::types::packet::PacketData;
use namada_sdk::ibc::clients::tendermint::client_state::ClientState;
use namada_sdk::ibc::clients::tendermint::consensus_state::ConsensusState;
use namada_sdk::ibc::clients::tendermint::types::{
    AllowUpdate, ClientState as ClientStateType,
    ConsensusState as ConsensusStateType, TrustThreshold,
};
use namada_sdk::ibc::core::channel::types::Version as ChannelVersion;
use namada_sdk::ibc::core::channel::types::channel::{
    ChannelEnd, Counterparty as ChannelCounterparty, Order, State,
};
use namada_sdk::ibc::core::channel::types::timeout::{
    TimeoutHeight, TimeoutTimestamp,
};
use namada_sdk::ibc::core::client::types::Height as IbcHeight;
use namada_sdk::ibc::core::commitment_types::commitment::{
    CommitmentPrefix, CommitmentRoot,
};
use namada_sdk::ibc::core::commitment_types::specs::ProofSpecs;
use namada_sdk::ibc::core::connection::types::version::Version;
use namada_sdk::ibc::core::connection::types::{
    ConnectionEnd, Counterparty, State as ConnectionState,
};
use namada_sdk::ibc::core::host::types::identifiers::{
    ChainId as IbcChainId, ChannelId as NamadaChannelId, ChannelId, ClientId,
    ConnectionId, ConnectionId as NamadaConnectionId, PortId as NamadaPortId,
    PortId,
};
use namada_sdk::ibc::core::host::types::path::{
    ClientConsensusStatePath, ClientStatePath, Path as IbcPath,
};
use namada_sdk::ibc::primitives::proto::{Any, Protobuf};
use namada_sdk::ibc::primitives::{IntoTimestamp, Timestamp as IbcTimestamp};
use namada_sdk::ibc::storage::{
    channel_key, connection_key, mint_limit_key, port_key, throughput_limit_key,
};
use namada_sdk::ibc::{COMMITMENT_PREFIX, MsgTransfer};
use namada_sdk::io::{Client, NamadaIo, StdIo};
use namada_sdk::key::common::SecretKey;
use namada_sdk::masp::shielded_wallet::ShieldedApi;
use namada_sdk::masp::utils::RetryStrategy;
use namada_sdk::masp::{
    self, ContextSyncStatus, DispatcherCache, MaspTransferData,
    ShieldedContext, ShieldedUtils, ShieldedWallet, VersionedWallet,
    VersionedWalletRef,
};
use namada_sdk::queries::{
    EncodedResponseQuery, RPC, RequestCtx, RequestQuery, Router,
};
use namada_sdk::state::StorageRead;
use namada_sdk::state::write_log::StorageModification;
use namada_sdk::storage::{Key, KeySeg, TxIndex};
use namada_sdk::time::DateTimeUtc;
use namada_sdk::token::{self, Amount, DenominatedAmount, Transfer};
use namada_sdk::tx::data::pos::Bond;
use namada_sdk::tx::data::{
    BatchedTxResult, Fee, TxResult, VpsResult, compute_inner_tx_hash,
};
use namada_sdk::tx::event::{Batch, MaspEvent, MaspTxRef, new_tx_event};
use namada_sdk::tx::{
    Authorization, BatchedTx, BatchedTxRef, Code, Data, IndexedTx, Section, Tx,
};
pub use namada_sdk::tx::{
    TX_BECOME_VALIDATOR_WASM, TX_BOND_WASM, TX_BRIDGE_POOL_WASM,
    TX_CHANGE_COMMISSION_WASM as TX_CHANGE_VALIDATOR_COMMISSION_WASM,
    TX_CHANGE_CONSENSUS_KEY_WASM,
    TX_CHANGE_METADATA_WASM as TX_CHANGE_VALIDATOR_METADATA_WASM,
    TX_CLAIM_REWARDS_WASM, TX_DEACTIVATE_VALIDATOR_WASM, TX_IBC_WASM,
    TX_INIT_ACCOUNT_WASM, TX_INIT_PROPOSAL as TX_INIT_PROPOSAL_WASM,
    TX_REACTIVATE_VALIDATOR_WASM, TX_REDELEGATE_WASM, TX_RESIGN_STEWARD,
    TX_REVEAL_PK as TX_REVEAL_PK_WASM, TX_TRANSFER_WASM, TX_UNBOND_WASM,
    TX_UNJAIL_VALIDATOR_WASM, TX_UPDATE_ACCOUNT_WASM,
    TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL as TX_VOTE_PROPOSAL_WASM,
    TX_WITHDRAW_WASM, VP_USER_WASM,
};
use namada_sdk::wallet::{DatedSpendingKey, Wallet};
use namada_sdk::{
    Namada, NamadaImpl, PaymentAddress, TransferSource, TransferTarget,
    parameters, proof_of_stake, tendermint,
};
use namada_test_utils::tx_data::TxWriteData;
use namada_vm::wasm::run;
use rand_core::OsRng;
use tempfile::TempDir;

use crate::config::TendermintMode;
use crate::config::global::GlobalConfig;
use crate::shell::Shell;
use crate::tendermint::abci::request::InitChain;
use crate::tendermint_proto::google::protobuf::Timestamp;
use crate::{config, dry_run_tx, tendermint_rpc};

pub const WASM_DIR: &str = "../../wasm";

pub const ALBERT_PAYMENT_ADDRESS: &str = "albert_payment";
pub const ALBERT_SPENDING_KEY: &str = "albert_spending";
pub const ALBERT_KEY: &str = "albert_key";
pub const BERTHA_PAYMENT_ADDRESS: &str = "bertha_payment";
const BERTHA_SPENDING_KEY: &str = "bertha_spending";

const FILE_NAME: &str = "shielded.dat";
const TMP_FILE_NAME: &str = "shielded.tmp";
const SPECULATIVE_FILE_NAME: &str = "speculative_shielded.dat";
const SPECULATIVE_TMP_FILE_NAME: &str = "speculative_shielded.tmp";
const CACHE_FILE_NAME: &str = "shielded_sync.cache";
const CACHE_FILE_TMP_PREFIX: &str = "shielded_sync.cache.tmp";

/// For `tracing_subscriber`, which fails if called more than once in the same
/// process
static SHELL_INIT: Once = Once::new();

pub struct BenchShellInner {
    pub inner: Shell,
    // Cache of the masp transactions and their changed keys in the last block
    // committed, the tx index coincides with the index in this collection
    pub last_block_masp_txs: Vec<(Tx, BTreeSet<Key>)>,
    // NOTE: Temporary directory should be dropped last since Shell need to
    // flush data on drop
    tempdir: TempDir,
}

impl BenchShellInner {
    pub fn generate_tx(
        &self,
        wasm_code_path: &str,
        data: impl BorshSerialize,
        shielded: Option<Transaction>,
        extra_sections: Option<Vec<Section>>,
        signers: Vec<&SecretKey>,
    ) -> BatchedTx {
        let mut tx = Tx::from_type(namada_sdk::tx::data::TxType::Raw);

        // NOTE: here we use the code hash to avoid including the cost for the
        // wasm validation. The wasm codes (both txs and vps) are always
        // in cache so we don't end up computing the cost to read and
        // compile the code which is the desired behaviour
        let code_hash = self
            .read_storage_key(&Key::wasm_hash(wasm_code_path))
            .unwrap();
        tx.set_code(Code::from_hash(
            code_hash,
            Some(wasm_code_path.to_string()),
        ));
        tx.set_data(Data::new(borsh::to_vec(&data).unwrap()));

        if let Some(transaction) = shielded {
            tx.add_section(Section::MaspTx(transaction));
        }

        if let Some(sections) = extra_sections {
            for section in sections {
                tx.add_section(section);
            }
        }

        for signer in signers {
            tx.add_section(Section::Authorization(Authorization::new(
                vec![tx.raw_header_hash()],
                [(0, signer.clone())].into_iter().collect(),
                None,
            )));
        }

        let cmt = tx.first_commitments().unwrap().clone();
        tx.batch_tx(cmt)
    }

    pub fn generate_ibc_tx(
        &self,
        wasm_code_path: &str,
        data: Vec<u8>,
    ) -> BatchedTx {
        // This function avoid serializaing the tx data with Borsh
        let mut tx = Tx::from_type(namada_sdk::tx::data::TxType::Raw);
        let code_hash = self
            .read_storage_key(&Key::wasm_hash(wasm_code_path))
            .unwrap();
        tx.set_code(Code::from_hash(
            code_hash,
            Some(wasm_code_path.to_string()),
        ));

        tx.set_data(Data::new(data));
        // NOTE: the Ibc VP doesn't actually check the signature
        let cmt = tx.first_commitments().unwrap().clone();
        tx.batch_tx(cmt)
    }

    pub fn generate_ibc_transfer_tx(&self) -> BatchedTx {
        let token = PrefixedCoin {
            denom: address::testing::nam().to_string().parse().unwrap(),
            amount: Amount::native_whole(1000)
                .to_string_native()
                .split('.')
                .next()
                .unwrap()
                .to_string()
                .parse()
                .unwrap(),
        };

        let timeout_height = TimeoutHeight::At(IbcHeight::new(0, 100).unwrap());

        #[allow(clippy::disallowed_methods)]
        let now: namada_sdk::tendermint::Time =
            DateTimeUtc::now().try_into().unwrap();
        let now: IbcTimestamp = now.into_timestamp().unwrap();
        let timeout_timestamp =
            (now + std::time::Duration::new(3600, 0)).unwrap();

        let message = IbcMsgTransfer {
            port_id_on_a: PortId::transfer(),
            chan_id_on_a: ChannelId::new(5),
            packet_data: PacketData {
                token,
                sender: defaults::albert_address().to_string().into(),
                receiver: defaults::bertha_address().to_string().into(),
                memo: "".parse().unwrap(),
            },
            timeout_height_on_b: timeout_height,
            timeout_timestamp_on_b: TimeoutTimestamp::At(timeout_timestamp),
        };

        let msg = MsgTransfer::<token::Transfer> {
            message,
            transfer: None,
        };

        self.generate_ibc_tx(TX_IBC_WASM, msg.serialize_to_vec())
    }

    /// Execute the tx and return a set of verifiers inserted by the tx.
    pub fn execute_tx(
        &mut self,
        batched_tx: &BatchedTxRef<'_>,
    ) -> BTreeSet<Address> {
        let gas_meter = RefCell::new(TxGasMeter::new(u64::MAX, 1));
        run::tx(
            &mut self.inner.state,
            &gas_meter,
            None,
            &TxIndex(0),
            batched_tx.tx,
            batched_tx.cmt,
            &mut self.inner.vp_wasm_cache,
            &mut self.inner.tx_wasm_cache,
            run::GasMeterKind::MutGlobal,
        )
        .unwrap()
    }

    pub fn advance_epoch(&mut self) {
        let params = proof_of_stake::storage::read_pos_params::<
            _,
            governance::Store<_>,
        >(&self.inner.state)
        .unwrap();

        self.state.in_mem_mut().block.epoch =
            self.state.in_mem().block.epoch.next();
        let current_epoch = self.state.in_mem().block.epoch;

        proof_of_stake::validator_set_update::copy_validator_sets_and_positions(
            &mut self.state,
            &params,
            current_epoch,
            current_epoch.unchecked_add(params.pipeline_len),
        )
        .unwrap();

        let masp_epoch_multiplier =
            parameters::read_masp_epoch_multiplier_parameter(&self.state)
                .unwrap();
        if self
            .state
            .is_masp_new_epoch(true, masp_epoch_multiplier)
            .unwrap()
        {
            token::conversion::update_allowed_conversions::<
                _,
                parameters::Store<_>,
                token::Store<_>,
            >(&mut self.state)
            .unwrap();
        }
    }

    pub fn init_ibc_client_state(&mut self, addr_key: Key) -> ClientId {
        // Set a dummy header
        self.state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .unwrap();
        // Set client state
        let client_id = ClientId::new("07-tendermint", 1).unwrap();
        let client_state_key = addr_key.join(&Key::from(
            IbcPath::ClientState(ClientStatePath(client_id.clone()))
                .to_string()
                .to_db_key(),
        ));
        let client_state = ClientStateType::new(
            IbcChainId::from_str(&ChainId::default().to_string()).unwrap(),
            TrustThreshold::ONE_THIRD,
            std::time::Duration::new(100, 0),
            std::time::Duration::new(200, 0),
            std::time::Duration::new(1, 0),
            IbcHeight::new(0, 1).unwrap(),
            ProofSpecs::cosmos(),
            vec![],
            AllowUpdate {
                after_expiry: true,
                after_misbehaviour: true,
            },
        )
        .unwrap()
        .into();
        let bytes = <ClientState as Protobuf<Any>>::encode_vec(client_state);
        self.state
            .db_write(&client_state_key, bytes)
            .expect("write failed");

        // Set consensus state
        #[allow(clippy::disallowed_methods)]
        let now: namada_sdk::tendermint::Time =
            DateTimeUtc::now().try_into().unwrap();
        let consensus_key = addr_key.join(&Key::from(
            IbcPath::ClientConsensusState(ClientConsensusStatePath {
                client_id: client_id.clone(),
                revision_number: 0,
                revision_height: 1,
            })
            .to_string()
            .to_db_key(),
        ));

        let consensus_state = ConsensusStateType {
            timestamp: now,
            root: CommitmentRoot::from_bytes(&[]),
            next_validators_hash: tendermint::Hash::Sha256([0u8; 32]),
        }
        .into();

        let bytes =
            <ConsensusState as Protobuf<Any>>::encode_vec(consensus_state);
        self.state.db_write(&consensus_key, bytes).unwrap();

        client_id
    }

    pub fn init_ibc_connection(&mut self) -> (Key, ClientId) {
        // Set client state
        let addr_key =
            Key::from(Address::Internal(InternalAddress::Ibc).to_db_key());
        let client_id = self.init_ibc_client_state(addr_key.clone());

        // Set connection open
        let connection = ConnectionEnd::new(
            ConnectionState::Open,
            client_id.clone(),
            Counterparty::new(
                client_id.clone(),
                Some(ConnectionId::new(1)),
                CommitmentPrefix::from(COMMITMENT_PREFIX.as_bytes().to_vec()),
            ),
            Version::compatibles(),
            std::time::Duration::new(100, 0),
        )
        .unwrap();

        let connection_key = connection_key(&NamadaConnectionId::new(1));
        self.state
            .db_write(&connection_key, connection.encode_vec())
            .unwrap();

        // Set port
        let port_key = port_key(&NamadaPortId::transfer());

        let index_key = addr_key
            .join(&Key::from("capabilities/index".to_string().to_db_key()));
        self.state.db_write(&index_key, 1u64.to_be_bytes()).unwrap();
        self.state.db_write(&port_key, 1u64.to_be_bytes()).unwrap();
        let cap_key =
            addr_key.join(&Key::from("capabilities/1".to_string().to_db_key()));
        self.state
            .db_write(&cap_key, PortId::transfer().as_bytes())
            .unwrap();

        (addr_key, client_id)
    }

    pub fn init_ibc_channel(&mut self) {
        let _ = self.init_ibc_connection();

        // Set Channel open
        let counterparty = ChannelCounterparty::new(
            PortId::transfer(),
            Some(ChannelId::new(5)),
        );
        let channel = ChannelEnd::new(
            State::Open,
            Order::Unordered,
            counterparty,
            vec![ConnectionId::new(1)],
            ChannelVersion::new("ics20-1".to_string()),
        )
        .unwrap();
        let channel_key =
            channel_key(&NamadaPortId::transfer(), &NamadaChannelId::new(5));
        self.state
            .db_write(&channel_key, channel.encode_vec())
            .unwrap();
    }

    pub fn enable_ibc_transfer(&mut self) {
        let token = address::testing::nam();
        let mint_limit_key = mint_limit_key(&token);
        self.state
            .db_write(&mint_limit_key, Amount::max_signed().serialize_to_vec())
            .unwrap();
        let throughput_limit_key = throughput_limit_key(&token);
        self.state
            .db_write(
                &throughput_limit_key,
                Amount::max_signed().serialize_to_vec(),
            )
            .unwrap();
    }

    // Update the block height in state to guarantee a valid response to the
    // client queries
    pub fn commit_block(&mut self) {
        // Update the MASP commitment tree anchor if the tree was updated
        let tree_key = token::storage_key::masp_commitment_tree_key();
        if let Some(StorageModification::Write { value }) = self
            .state
            .write_log()
            .read(&tree_key)
            .expect("Must be able to read masp commitment tree")
            .0
        {
            let updated_tree =
                CommitmentTree::<Node>::try_from_slice(value).unwrap();
            let anchor_key = token::storage_key::masp_commitment_anchor_key(
                updated_tree.root(),
            );
            self.state
                .db_write(&anchor_key, ().serialize_to_vec())
                .unwrap();
        }

        let last_height = self.inner.state.in_mem().get_last_block_height();
        self.inner
            .state
            .in_mem_mut()
            .begin_block(last_height.next_height())
            .unwrap();

        self.inner.commit();
        self.inner
            .state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .unwrap();
    }

    // Commit a masp transaction and cache the tx and the changed keys for
    // client queries
    pub fn commit_masp_tx(&mut self, mut masp_tx: Tx) {
        use namada_sdk::key::RefTo;
        masp_tx.add_wrapper(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(0.into()),
                token: self.state.in_mem().native_token.clone(),
            },
            defaults::albert_keypair().ref_to(),
            0.into(),
        );
        self.last_block_masp_txs
            .push((masp_tx, self.state.write_log().get_keys()));
        self.state.commit_tx_batch();
    }
}

impl Deref for BenchShellInner {
    type Target = Shell;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for BenchShellInner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[derive(Clone)]
pub struct BenchShell {
    inner: Arc<RwLock<BenchShellInner>>,
}

impl BenchShell {
    pub fn read(&self) -> RwLockReadGuard<'_, BenchShellInner> {
        self.inner.read().unwrap()
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, BenchShellInner> {
        self.inner.write().unwrap()
    }
}

impl Default for BenchShell {
    fn default() -> Self {
        SHELL_INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env(),
                )
                .init();
        });

        let (sender, _) = tokio::sync::mpsc::unbounded_channel();
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().canonicalize().unwrap();

        let shell = Shell::new(
            config::Ledger::new(path, Default::default(), TendermintMode::Full),
            WASM_DIR.into(),
            sender,
            None,
            None,
            None,
            50 * 1024 * 1024, // 50 kiB
            50 * 1024 * 1024, // 50 kiB
        );
        let mut bench_shell = BenchShellInner {
            inner: shell,
            last_block_masp_txs: vec![],
            tempdir,
        };

        bench_shell
            .init_chain(
                InitChain {
                    time: Timestamp {
                        seconds: 0,
                        nanos: 0,
                    }
                    .try_into()
                    .unwrap(),
                    chain_id: ChainId::default().to_string(),
                    consensus_params: tendermint::consensus::params::Params {
                        block: tendermint::block::Size {
                            max_bytes: 0,
                            max_gas: 0,
                            time_iota_ms: 0,
                        },
                        evidence: tendermint::evidence::Params {
                            max_age_num_blocks: 0,
                            max_age_duration: tendermint::evidence::Duration(
                                core::time::Duration::MAX,
                            ),
                            max_bytes: 0,
                        },
                        validator:
                            tendermint::consensus::params::ValidatorParams {
                                pub_key_types: vec![],
                            },
                        version: None,
                        abci: tendermint::consensus::params::AbciParams {
                            vote_extensions_enable_height: None,
                        },
                    },
                    validators: vec![],
                    app_state_bytes: vec![].into(),
                    initial_height: 0_u32.into(),
                },
                2,
            )
            .unwrap();
        // Commit tx hashes to storage
        bench_shell.commit_block();

        // Bond from Albert to validator
        let bond = Bond {
            validator: defaults::validator_address(),
            amount: Amount::native_whole(1000),
            source: Some(defaults::albert_address()),
        };
        let params = proof_of_stake::storage::read_pos_params::<
            _,
            governance::Store<_>,
        >(&bench_shell.state)
        .unwrap();
        let signed_tx = bench_shell.generate_tx(
            TX_BOND_WASM,
            bond,
            None,
            None,
            vec![&defaults::albert_keypair()],
        );

        bench_shell.execute_tx(&signed_tx.to_ref());
        bench_shell.state.commit_tx_batch();

        // Initialize governance proposal
        let content_section = Section::ExtraData(Code::new(
            vec![],
            Some(TX_INIT_PROPOSAL_WASM.to_string()),
        ));
        let voting_start_epoch =
            Epoch(2 + params.pipeline_len + params.unbonding_len);
        let signed_tx = bench_shell.generate_tx(
            TX_INIT_PROPOSAL_WASM,
            InitProposalData {
                content: content_section.get_hash(),
                author: defaults::albert_address(),
                r#type: ProposalType::Default,
                voting_start_epoch,
                voting_end_epoch: voting_start_epoch.unchecked_add(3_u64),
                activation_epoch: voting_start_epoch.unchecked_add(9_u64),
            },
            None,
            Some(vec![content_section]),
            vec![&defaults::albert_keypair()],
        );

        bench_shell.execute_tx(&signed_tx.to_ref());
        bench_shell.state.commit_tx_batch();
        bench_shell.commit_block();

        // Advance epoch for pos benches
        for _ in 0..=(params.pipeline_len + params.unbonding_len) {
            bench_shell.advance_epoch();
        }
        // Must start after current epoch
        debug_assert_eq!(
            bench_shell.state.get_block_epoch().unwrap().next(),
            voting_start_epoch
        );

        BenchShell {
            inner: Arc::new(RwLock::new(bench_shell)),
        }
    }
}

pub fn generate_foreign_key_tx(signer: &SecretKey) -> BatchedTx {
    let wasm_code =
        std::fs::read("../../wasm_for_tests/tx_write.wasm").unwrap();

    let mut tx = Tx::from_type(namada_sdk::tx::data::TxType::Raw);
    tx.set_code(Code::new(wasm_code, None));
    tx.set_data(Data::new(
        TxWriteData {
            key: Key::from("bench_foreign_key".to_string().to_db_key()),
            value: vec![0; 64],
        }
        .serialize_to_vec(),
    ));
    tx.add_section(Section::Authorization(Authorization::new(
        vec![tx.raw_header_hash()],
        [(0, signer.clone())].into_iter().collect(),
        None,
    )));

    let cmt = tx.first_commitments().unwrap().clone();
    tx.batch_tx(cmt)
}

pub struct BenchShieldedCtx {
    pub shielded: ShieldedContext<BenchShieldedUtils>,
    pub shell: BenchShell,
    pub wallet: Wallet<CliWalletUtils>,
}

#[derive(Debug)]
struct WrapperTempDir(TempDir);

// Mock the required traits for ShieldedUtils

impl Default for WrapperTempDir {
    fn default() -> Self {
        Self(TempDir::new().unwrap())
    }
}

impl Clone for WrapperTempDir {
    fn clone(&self) -> Self {
        Self(TempDir::new().unwrap())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct BenchShieldedUtils {
    #[borsh(skip)]
    context_dir: WrapperTempDir,
}

impl BenchShieldedUtils {
    fn atomic_file_write(
        &self,
        tmp_file_name: impl AsRef<std::path::Path>,
        file_name: impl AsRef<std::path::Path>,
        data: impl BorshSerialize,
    ) -> std::io::Result<()> {
        let tmp_path = self.context_dir.0.path().join(&tmp_file_name);
        {
            // First serialize the shielded context into a temporary file.
            // Inability to create this file implies a simultaneuous write
            // is in progress. In this case, immediately
            // fail. This is unproblematic because the data
            // intended to be stored can always be re-fetched
            // from the blockchain.
            let mut ctx_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(tmp_path.clone())?;
            let mut bytes = Vec::new();
            data.serialize(&mut bytes).unwrap_or_else(|e| {
                panic!(
                    "cannot serialize data to {} with error: {}",
                    file_name.as_ref().to_string_lossy(),
                    e,
                )
            });
            ctx_file.write_all(&bytes[..])?;
        }
        // Atomically update the old shielded context file with new data.
        // Atomicity is required to prevent other client instances from
        // reading corrupt data.
        std::fs::rename(tmp_path, self.context_dir.0.path().join(file_name))
    }
}

#[async_trait::async_trait(?Send)]
impl ShieldedUtils for BenchShieldedUtils {
    fn local_tx_prover(&self) -> LocalTxProver {
        if let Ok(params_dir) = std::env::var(masp::ENV_VAR_MASP_PARAMS_DIR) {
            let params_dir = PathBuf::from(params_dir);
            let spend_path = params_dir.join(masp::SPEND_NAME);
            let convert_path = params_dir.join(masp::CONVERT_NAME);
            let output_path = params_dir.join(masp::OUTPUT_NAME);
            LocalTxProver::new(&spend_path, &output_path, &convert_path)
        } else {
            LocalTxProver::with_default_location()
                .expect("unable to load MASP Parameters")
        }
    }

    /// Try to load the last saved shielded context from the given context
    /// directory. If this fails, then leave the current context unchanged.
    async fn load<U: ShieldedUtils>(
        &self,
        ctx: &mut ShieldedWallet<U>,
        force_confirmed: bool,
    ) -> std::io::Result<()> {
        // Try to load shielded context from file
        let file_name = if force_confirmed {
            FILE_NAME
        } else {
            match ctx.sync_status {
                ContextSyncStatus::Confirmed => FILE_NAME,
                ContextSyncStatus::Speculative => SPECULATIVE_FILE_NAME,
            }
        };
        let mut ctx_file = match File::open(
            self.context_dir.0.path().to_path_buf().join(file_name),
        ) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // a missing file means there is nothing to load.
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let mut bytes = Vec::new();
        ctx_file.read_to_end(&mut bytes)?;
        // Fill the supplied context with the deserialized object
        let wallet = match VersionedWallet::<U>::deserialize(&mut &bytes[..]) {
            Ok(w) => w.migrate().map_err(std::io::Error::other)?,
            Err(_) => ShieldedWallet::<U>::deserialize(&mut &bytes[..])?,
        };
        *ctx = ShieldedWallet {
            utils: ctx.utils.clone(),
            ..wallet
        };
        Ok(())
    }

    /// Save this shielded context into its associated context directory
    async fn save<'a, U: ShieldedUtils>(
        &'a self,
        ctx: VersionedWalletRef<'a, U>,
        sync_status: ContextSyncStatus,
    ) -> std::io::Result<()> {
        let (tmp_file_name, file_name) = match sync_status {
            ContextSyncStatus::Confirmed => (TMP_FILE_NAME, FILE_NAME),
            ContextSyncStatus::Speculative => {
                (SPECULATIVE_TMP_FILE_NAME, SPECULATIVE_FILE_NAME)
            }
        };
        let tmp_path =
            self.context_dir.0.path().to_path_buf().join(tmp_file_name);
        {
            // First serialize the shielded context into a temporary file.
            // Inability to create this file implies a simultaneuous write is in
            // progress. In this case, immediately fail. This is unproblematic
            // because the data intended to be stored can always be re-fetched
            // from the blockchain.
            let mut ctx_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(tmp_path.clone())?;
            let mut bytes = Vec::new();
            ctx.serialize(&mut bytes)
                .expect("cannot serialize shielded context");
            ctx_file.write_all(&bytes[..])?;
        }
        // Atomically update the old shielded context file with new data.
        // Atomicity is required to prevent other client instances from reading
        // corrupt data.
        std::fs::rename(
            tmp_path,
            self.context_dir.0.path().to_path_buf().join(file_name),
        )?;

        // Remove the speculative file if present since it's state is
        // overwritten by the confirmed one we just saved
        if let ContextSyncStatus::Confirmed = sync_status {
            let _ = std::fs::remove_file(
                self.context_dir
                    .0
                    .path()
                    .to_path_buf()
                    .join(SPECULATIVE_FILE_NAME),
            );
        }
        Ok(())
    }

    async fn cache_save(&self, cache: &DispatcherCache) -> std::io::Result<()> {
        let tmp_file_name = {
            let t = tempfile::Builder::new()
                .prefix(CACHE_FILE_TMP_PREFIX)
                .tempfile()?;
            t.path().file_name().unwrap().to_owned()
        };

        self.atomic_file_write(tmp_file_name, CACHE_FILE_NAME, cache)
    }

    async fn cache_load(&self) -> std::io::Result<DispatcherCache> {
        let file_name = self.context_dir.0.path().join(CACHE_FILE_NAME);
        let mut file = File::open(file_name)?;
        DispatcherCache::try_from_reader(&mut file)
    }
}

#[async_trait::async_trait(?Send)]
impl Client for BenchShell {
    type Error = std::io::Error;

    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> Result<EncodedResponseQuery, Self::Error> {
        let data = data.unwrap_or_default();
        let height = height.unwrap_or_default();

        let request = RequestQuery {
            data: data.into(),
            path,
            height: height.try_into().unwrap(),
            prove,
        };

        let shell = self.read();

        if request.path == RPC.shell().dry_run_tx_path() {
            dry_run_tx(
                // This is safe because nothing else is using `self.state`
                // concurrently and the `TempWlState` will be dropped right
                // after dry-run.
                unsafe { shell.state.read_only().with_static_temp_write_log() },
                shell.vp_wasm_cache.read_only(),
                shell.tx_wasm_cache.read_only(),
                &request,
            )
        } else {
            let ctx = RequestCtx {
                state: &shell.state,
                event_log: shell.event_log(),
                vp_wasm_cache: shell.vp_wasm_cache.read_only(),
                tx_wasm_cache: shell.tx_wasm_cache.read_only(),
                storage_read_past_height_limit: None,
            };
            RPC.handle(ctx, &request)
        }
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::NotFound))
    }

    async fn perform<R>(
        &self,
        _request: R,
    ) -> Result<R::Output, tendermint_rpc::Error>
    where
        R: tendermint_rpc::SimpleRequest,
    {
        unimplemented!(
            "Arbitrary queries are not implemented in the benchmarks context"
        );
    }

    async fn block<H>(
        &self,
        height: H,
    ) -> Result<tendermint_rpc::endpoint::block::Response, tendermint_rpc::Error>
    where
        H: TryInto<tendermint::block::Height> + Send,
    {
        // NOTE: atm this is only needed to query blocks at a specific height
        // for masp transactions
        let height = BlockHeight(
            height
                .try_into()
                .map_err(|_| {
                    tendermint_rpc::Error::parse(
                        "Failed to cast block height".to_string(),
                    )
                })?
                .into(),
        );

        let shell = self.read();

        // Given the way we setup and run benchmarks, the masp transactions can
        // only present in the last block, we can mock the previous
        // responses with an empty set of transactions
        let last_block_txs =
            if height == shell.inner.state.in_mem().get_last_block_height() {
                shell.last_block_masp_txs.clone()
            } else {
                vec![]
            };
        Ok(tendermint_rpc::endpoint::block::Response {
            block_id: tendermint::block::Id {
                hash: tendermint::Hash::None,
                part_set_header: tendermint::block::parts::Header::default(),
            },
            block: tendermint::block::Block::new(
                tendermint::block::Header {
                    version: tendermint::block::header::Version {
                        block: 0,
                        app: 0,
                    },
                    chain_id: shell
                        .inner
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
                    proposer_address: tendermint::account::Id::new([0u8; 20]),
                },
                last_block_txs
                    .into_iter()
                    .map(|(tx, _)| tx.to_bytes())
                    .collect(),
                tendermint::evidence::List::default(),
                None,
            ),
        })
    }

    async fn block_results<H>(
        &self,
        height: H,
    ) -> Result<
        tendermint_rpc::endpoint::block_results::Response,
        tendermint_rpc::Error,
    >
    where
        H: TryInto<namada_sdk::tendermint::block::Height> + Send,
    {
        // NOTE: atm this is only needed to query block results at a specific
        // height for masp transactions
        let height = height.try_into().map_err(|_| {
            tendermint_rpc::Error::parse(
                "Failed to cast block height".to_string(),
            )
        })?;

        let shell = self.read();

        // We can expect all the masp tranfers to have happened only in the last
        // block
        let end_block_events = if height.value()
            == shell.inner.state.in_mem().get_last_block_height().0
        {
            let mut res = vec![];
            for (idx, (tx, changed_keys)) in
                shell.last_block_masp_txs.iter().enumerate()
            {
                let tx_result = {
                    let mut batch_results = TxResult::new();
                    batch_results.insert_inner_tx_result(
                        tx.wrapper_hash().as_ref(),
                        either::Right(tx.first_commitments().unwrap()),
                        Ok(BatchedTxResult {
                            changed_keys: changed_keys.to_owned(),
                            vps_result: VpsResult::default(),
                            initialized_accounts: vec![],
                            events: BTreeSet::default(),
                        }),
                    );
                    batch_results
                };
                let tx_event: Event = new_tx_event(tx, height.value())
                    .with(Batch(&tx_result))
                    .into();
                // Expect a single masp tx in the batch
                let masp_ref = tx.sections.iter().find_map(|section| {
                    if let Section::MaspTx(transaction) = section {
                        Some(MaspTxRef::MaspSection(transaction.txid().into()))
                    } else {
                        None
                    }
                });

                let first_inner_tx_hash = compute_inner_tx_hash(
                    tx.wrapper_hash().as_ref(),
                    Either::Right(tx.first_commitments().unwrap()),
                );
                let masp_event = masp_ref.map(|data| {
                    let masp_event: Event = MaspEvent {
                        tx_index: IndexedTx {
                            block_height: namada_sdk::chain::BlockHeight(
                                u64::from(height),
                            ),
                            block_index: TxIndex::must_from_usize(idx),
                            batch_index: Some(0),
                        },
                        kind: namada_sdk::tx::event::MaspEventKind::Transfer,
                        data,
                    }
                    .with(TxHash(tx.header_hash()))
                    .with(InnerTxHash(first_inner_tx_hash))
                    .into();
                    masp_event
                });

                res.push(namada_sdk::tendermint::abci::Event::from(tx_event));

                if let Some(event) = masp_event {
                    res.push(namada_sdk::tendermint::abci::Event::from(event));
                }
            }
            Some(res)
        } else {
            None
        };

        Ok(tendermint_rpc::endpoint::block_results::Response {
            height,
            txs_results: None,
            finalize_block_events: vec![],
            begin_block_events: None,
            end_block_events,
            validator_updates: vec![],
            consensus_param_updates: None,
            app_hash: namada_sdk::tendermint::hash::AppHash::default(),
        })
    }
}

impl Default for BenchShieldedCtx {
    fn default() -> Self {
        let shell = BenchShell::default();

        let mut chain_ctx = {
            let shell_read = shell.read();

            let base_dir = shell_read.tempdir.as_ref().canonicalize().unwrap();

            // Create a global config and an empty wallet in the chain dir -
            // this is needed in `Context::new`
            let config = GlobalConfig::new(shell_read.inner.chain_id.clone());
            config.write(&base_dir).unwrap();
            let wallet = namada_apps_lib::wallet::CliWalletUtils::new(
                base_dir.join(shell_read.inner.chain_id.as_str()),
            );
            wallet.save().unwrap();

            let ctx = Context::new::<StdIo>(cli::args::Global {
                is_pre_genesis: false,
                chain_id: Some(shell_read.inner.chain_id.clone()),
                base_dir,
                wasm_dir: Some(WASM_DIR.into()),
            })
            .unwrap();

            ctx.take_chain_or_exit()
        };

        // Generate spending key for Albert and Bertha
        chain_ctx.wallet.gen_store_spending_key(
            ALBERT_SPENDING_KEY.to_string(),
            None,
            None,
            true,
            &mut OsRng,
        );
        chain_ctx.wallet.gen_store_spending_key(
            BERTHA_SPENDING_KEY.to_string(),
            None,
            None,
            true,
            &mut OsRng,
        );
        namada_apps_lib::wallet::save(&chain_ctx.wallet).unwrap();

        // Generate payment addresses for both Albert and Bertha
        for (alias, viewing_alias) in [
            (ALBERT_PAYMENT_ADDRESS, ALBERT_SPENDING_KEY),
            (BERTHA_PAYMENT_ADDRESS, BERTHA_SPENDING_KEY),
        ]
        .map(|(p, s)| (p.to_owned(), s.to_owned()))
        {
            let viewing_key: FromContext<namada_sdk::ExtendedViewingKey> =
                FromContext::new(
                    chain_ctx
                        .wallet
                        .find_viewing_key(viewing_alias)
                        .unwrap()
                        .to_string(),
                );
            let viewing_key = ExtendedFullViewingKey::from(
                chain_ctx.get_cached(&viewing_key),
            )
            .fvk
            .vk;
            let (div, _g_d) = masp::find_valid_diversifier(&mut OsRng);
            let payment_addr = viewing_key.to_payment_address(div).unwrap();
            let _ = chain_ctx
                .wallet
                .insert_payment_addr(
                    alias,
                    PaymentAddress::from(payment_addr),
                    true,
                )
                .unwrap();
        }
        _ = chain_ctx.wallet.gen_store_secret_key(
            SchemeType::Ed25519,
            Some(ALBERT_KEY.to_string()),
            true,
            None,
            &mut OsRng,
        );

        namada_apps_lib::wallet::save(&chain_ctx.wallet).unwrap();

        Self {
            shielded: ShieldedContext::default(),
            shell,
            wallet: chain_ctx.wallet,
        }
    }
}

impl BenchShieldedCtx {
    pub fn generate_masp_tx(
        mut self,
        amount: Amount,
        source: TransferSource,
        target: TransferTarget,
    ) -> (Self, BatchedTx) {
        let denominated_amount = DenominatedAmount::native(amount);
        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        let spending_key = self
            .wallet
            .find_spending_key(ALBERT_SPENDING_KEY, None)
            .unwrap();
        let spending_key = DatedSpendingKey::new(
            spending_key,
            self.wallet.find_birthday(ALBERT_SPENDING_KEY).copied(),
        );
        let shielding_fee_key =
            self.wallet.find_public_key(ALBERT_KEY).unwrap();
        self.shielded = async_runtime
            .block_on(namada_apps_lib::client::masp::syncing(
                self.shielded,
                self.shell.clone(),
                ShieldedSync {
                    ledger_address: FromStr::from_str("http://127.0.0.1:1337")
                        .unwrap(),
                    last_query_height: None,
                    spending_keys: vec![spending_key],
                    viewing_keys: vec![],
                    with_indexer: None,
                    wait_for_last_query_height: false,
                    max_concurrent_fetches: 100,
                    retry_strategy: RetryStrategy::Forever,
                    block_batch_size: 10,
                },
                &StdIo,
            ))
            .unwrap();
        let native_token =
            self.shell.read().state.in_mem().native_token.clone();
        let namada = NamadaImpl::native_new(
            self.shell,
            self.wallet,
            self.shielded.into(),
            StdIo,
            native_token.clone(),
        );
        let masp_transfer_data = MaspTransferData {
            sources: vec![(
                source.clone(),
                address::testing::nam(),
                denominated_amount,
            )],
            targets: vec![(
                target.clone(),
                address::testing::nam(),
                denominated_amount,
            )],
        };
        let shielded = async_runtime
            .block_on(async {
                let expiration =
                    Namada::tx_builder(&namada).expiration.to_datetime();
                let mut shielded_ctx = namada.shielded_mut().await;
                shielded_ctx
                    .gen_shielded_transfer(
                        &namada,
                        masp_transfer_data,
                        None,
                        expiration,
                        &mut RngBuildParams::new(OsRng),
                    )
                    .await
            })
            .unwrap()
            .map(
                |masp::ShieldedTransfer {
                     builder: _,
                     masp_tx,
                     metadata: _,
                     epoch: _,
                 }| masp_tx,
            )
            .expect("MASP must have shielded part");

        let shielded_section_hash = shielded.txid().into();
        let tx = if source.effective_address() == MASP
            && target.effective_address() == MASP
        {
            namada.client().read().generate_tx(
                TX_TRANSFER_WASM,
                Transfer::masp(shielded_section_hash),
                Some(shielded),
                None,
                vec![&defaults::albert_keypair()],
            )
        } else if target.effective_address() == MASP {
            namada.client().read().generate_tx(
                TX_TRANSFER_WASM,
                Transfer::masp(shielded_section_hash)
                    .transfer(
                        source.effective_address(),
                        MASP,
                        address::testing::nam(),
                        DenominatedAmount::native(amount),
                    )
                    .unwrap(),
                Some(shielded),
                Some(vec![Section::MaspSustainabilityFee {
                    payer: shielding_fee_key,
                    token: native_token,
                    cmt: shielded_section_hash,
                }]),
                vec![&defaults::albert_keypair()],
            )
        } else {
            namada.client().read().generate_tx(
                TX_TRANSFER_WASM,
                Transfer::masp(shielded_section_hash)
                    .transfer(
                        MASP,
                        target.effective_address(),
                        address::testing::nam(),
                        DenominatedAmount::native(amount),
                    )
                    .unwrap(),
                Some(shielded),
                None,
                vec![&defaults::albert_keypair()],
            )
        };

        let NamadaImpl {
            client,
            wallet,
            shielded,
            ..
        } = namada;
        let ctx = Self {
            shielded: shielded.into_inner(),
            shell: client,
            wallet: wallet.into_inner(),
        };
        (ctx, tx)
    }

    pub fn generate_shielded_action(
        self,
        amount: Amount,
        source: TransferSource,
        target: String,
    ) -> (Self, BatchedTx) {
        let (ctx, tx) = self.generate_masp_tx(
            amount,
            source.clone(),
            TransferTarget::Ibc(target.clone()),
        );

        let token = PrefixedCoin {
            denom: address::testing::nam().to_string().parse().unwrap(),
            amount: amount
                .to_string_native()
                .split('.')
                .next()
                .unwrap()
                .to_string()
                .parse()
                .unwrap(),
        };
        let timeout_height = TimeoutHeight::At(IbcHeight::new(0, 100).unwrap());

        #[allow(clippy::disallowed_methods)]
        let now: namada_sdk::tendermint::Time =
            DateTimeUtc::now().try_into().unwrap();
        let now: IbcTimestamp = now.into_timestamp().unwrap();
        let timeout_timestamp =
            (now + std::time::Duration::new(3600, 0)).unwrap();
        let msg = IbcMsgTransfer {
            port_id_on_a: PortId::transfer(),
            chan_id_on_a: ChannelId::new(5),
            packet_data: PacketData {
                token,
                sender: source.effective_address().to_string().into(),
                receiver: target.into(),
                memo: "".parse().unwrap(),
            },
            timeout_height_on_b: timeout_height,
            timeout_timestamp_on_b: TimeoutTimestamp::At(timeout_timestamp),
        };

        let vectorized_transfer =
            Transfer::deserialize(&mut tx.tx.data(&tx.cmt).unwrap().as_slice())
                .unwrap();
        let sources =
            vec![vectorized_transfer.sources.into_iter().next().unwrap()]
                .into_iter()
                .collect();
        let targets =
            vec![vectorized_transfer.targets.into_iter().next().unwrap()]
                .into_iter()
                .collect();
        let transfer = Transfer {
            sources,
            targets,
            shielded_section_hash: Some(
                vectorized_transfer.shielded_section_hash.unwrap(),
            ),
        };
        let masp_tx = tx
            .tx
            .get_masp_section(&transfer.shielded_section_hash.unwrap())
            .unwrap()
            .clone();
        let msg = MsgTransfer::<token::Transfer> {
            message: msg,
            transfer: Some(transfer),
        };

        let mut ibc_tx = ctx
            .shell
            .read()
            .generate_ibc_tx(TX_IBC_WASM, msg.serialize_to_vec());
        ibc_tx.tx.add_masp_tx_section(masp_tx);

        (ctx, ibc_tx)
    }
}
