//! Test running well-formed inner WASM txs via finalize block handler.

#![no_main]
#![allow(clippy::disallowed_methods)]

use std::sync::Mutex;

use arbitrary::Arbitrary;
use data_encoding::HEXUPPER;
use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use namada_apps_lib::{tendermint, wallet};
use namada_core::key::PublicKeyTmRawHash;
use namada_node::shell;
use namada_node::shell::FinalizeBlockRequest;
use namada_node::shell::abci::{ProcessedTx, TxBytes, TxResult};
use namada_node::shell::test_utils::TestShell;
use namada_sdk::address::Address;
use namada_sdk::ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use namada_sdk::ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use namada_sdk::ibc::core::handler::types::msgs::MsgEnvelope;
use namada_sdk::key::common;
use namada_sdk::token::{self, DenominatedAmount};
use namada_sdk::tx::Tx;
use namada_sdk::{account, address, governance, storage, tx};
use namada_tx::data::{pgf, pos};

lazy_static! {
    static ref SHELL: Mutex<TestShell> = {
        let shell = shell::test_utils::setup();
        Mutex::new(shell)
    };
}

#[allow(clippy::large_enum_variant)]
#[derive(Arbitrary, Debug)]
enum TxKind {
    InitAccount(account::InitAccount),
    BecomeValidator(pos::BecomeValidator),
    UnjailValidator(Address),
    DeactivateValidator(Address),
    ReactivateValidator(Address),
    InitProposal(governance::InitProposalData),
    VoteProposal(governance::VoteProposalData),
    RevealPk(common::PublicKey),
    UpdateAccount(account::UpdateAccount),
    Transfer(token::Transfer),
    Ibc(IbcData),
    Bond(pos::Bond),
    Unbond(pos::Unbond),
    Withdraw(pos::Withdraw),
    Redelegate(pos::Redelegation),
    ClaimRewards(pos::ClaimRewards),
    ChangeCommission(pos::CommissionChange),
    ChangeConsensusKey(pos::ConsensusKeyChange),
    ChangeMetadata(pos::MetaDataChange),
    ResignSteward(Address),
    UpdateStewardCommission(pgf::UpdateStewardCommission),
}

#[derive(Arbitrary, Debug)]
enum IbcData {
    MsgEnvelope(MsgEnvelope),
    MsgTransfer(IbcMsgTransfer),
    MsgNftTransfer(IbcMsgNftTransfer),
    BorshMsgTransfer(namada_sdk::ibc::MsgTransfer<token::Transfer>),
    BorshMsgNftTransfer(namada_sdk::ibc::MsgNftTransfer<token::Transfer>),
}

fuzz_target!(|kinds: NonEmptyVec<TxKind>| run(kinds));

fn run(kinds: NonEmptyVec<TxKind>) {
    let kinds = kinds.into_vec();
    let mut shell = SHELL.lock().unwrap();

    // Construct the txs
    let mut txs_bytes: Vec<TxBytes> = Vec::with_capacity(kinds.len());
    let signer = wallet::defaults::albert_keypair();
    for kind in kinds {
        let mut tx = Tx::from_type(tx::data::TxType::Raw);

        use TxKind::*;
        let code_tag = match kind {
            InitAccount(data) => {
                tx.add_data(data);
                tx::TX_INIT_ACCOUNT_WASM
            }
            BecomeValidator(data) => {
                tx.add_data(data);
                tx::TX_BECOME_VALIDATOR_WASM
            }
            UnjailValidator(data) => {
                tx.add_data(data);
                tx::TX_UNJAIL_VALIDATOR_WASM
            }
            DeactivateValidator(data) => {
                tx.add_data(data);
                tx::TX_DEACTIVATE_VALIDATOR_WASM
            }
            ReactivateValidator(data) => {
                tx.add_data(data);
                tx::TX_REACTIVATE_VALIDATOR_WASM
            }
            InitProposal(data) => {
                tx.add_data(data);
                tx::TX_INIT_PROPOSAL
            }
            VoteProposal(data) => {
                tx.add_data(data);
                tx::TX_VOTE_PROPOSAL
            }
            RevealPk(data) => {
                tx.add_data(data);
                tx::TX_REVEAL_PK
            }
            UpdateAccount(data) => {
                tx.add_data(data);
                tx::TX_UPDATE_ACCOUNT_WASM
            }
            Transfer(data) => {
                tx.add_data(data);
                tx::TX_TRANSFER_WASM
            }
            Ibc(data) => {
                add_ibc_tx_data(&mut tx, data);
                tx::TX_IBC_WASM
            }
            Bond(data) => {
                tx.add_data(data);
                tx::TX_BOND_WASM
            }
            Unbond(data) => {
                tx.add_data(data);
                tx::TX_UNBOND_WASM
            }
            Withdraw(data) => {
                tx.add_data(data);
                tx::TX_WITHDRAW_WASM
            }
            Redelegate(data) => {
                tx.add_data(data);
                tx::TX_REDELEGATE_WASM
            }
            ClaimRewards(data) => {
                tx.add_data(data);
                tx::TX_CLAIM_REWARDS_WASM
            }
            ChangeCommission(data) => {
                tx.add_data(data);
                tx::TX_CHANGE_COMMISSION_WASM
            }
            ChangeConsensusKey(data) => {
                tx.add_data(data);
                tx::TX_CHANGE_CONSENSUS_KEY_WASM
            }
            ChangeMetadata(data) => {
                tx.add_data(data);
                tx::TX_CHANGE_METADATA_WASM
            }
            ResignSteward(data) => {
                tx.add_data(data);
                tx::TX_RESIGN_STEWARD
            }
            UpdateStewardCommission(data) => {
                tx.add_data(data);
                tx::TX_UPDATE_STEWARD_COMMISSION
            }
        };
        let code_hash = shell
            .read_storage_key(&storage::Key::wasm_hash(code_tag))
            .unwrap();
        tx.add_code_from_hash(code_hash, Some(code_tag.to_string()));

        tx.update_header(tx::data::TxType::Wrapper(Box::new(
            tx::data::WrapperTx::new(
                tx::data::Fee {
                    token: address::testing::nam(),
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                },
                signer.to_public(),
                1_000_000.into(),
            ),
        )));
        tx.add_section(tx::Section::Authorization(tx::Authorization::new(
            vec![tx.raw_header_hash()],
            [(0, signer.clone())].into_iter().collect(),
            None,
        )));

        txs_bytes.push(tx.to_bytes().into());
    }

    // Add a successful result for every tx
    let mut txs = Vec::with_capacity(txs_bytes.len());
    for tx in txs_bytes.into_iter() {
        let result = TxResult::default(); // default is success
        txs.push(ProcessedTx { tx, result });
    }

    // Run the txs via a `FinalizeBlock` request
    let proposer_pk = wallet::defaults::validator_keypair().to_public();
    let proposer_address_bytes = HEXUPPER
        .decode(proposer_pk.tm_raw_hash().as_bytes())
        .unwrap();
    let req = FinalizeBlockRequest {
        txs,
        proposer_address: tendermint::account::Id::try_from(
            proposer_address_bytes,
        )
        .unwrap(),
        ..Default::default()
    };
    let _event = shell.finalize_block(req).unwrap();

    // Commit the block
    shell.commit();
}

fn add_ibc_tx_data(tx: &mut Tx, data: IbcData) {
    use namada_sdk::ibc::primitives::ToProto;
    use prost::Message;
    match data {
        IbcData::MsgEnvelope(data) => {
            let proto_data = match data {
                MsgEnvelope::Client(data) => {
                    use namada_sdk::ibc::core::client::types::msgs::ClientMsg;
                    match data {
                        ClientMsg::CreateClient(data) => data.to_any(),
                        ClientMsg::UpdateClient(data) => data.to_any(),
                        ClientMsg::Misbehaviour(data) => data.to_any(),
                        ClientMsg::UpgradeClient(data) => data.to_any(),
                        ClientMsg::RecoverClient(data) => data.to_any(),
                    }
                }
                MsgEnvelope::Connection(data) => {
                    use namada_sdk::ibc::core::connection::types::msgs::ConnectionMsg;
                    match data {
                        ConnectionMsg::OpenInit(data) => data.to_any(),
                        ConnectionMsg::OpenTry(data) => data.to_any(),
                        ConnectionMsg::OpenAck(data) => data.to_any(),
                        ConnectionMsg::OpenConfirm(data) => data.to_any(),
                    }
                }
                MsgEnvelope::Channel(data) => {
                    use namada_sdk::ibc::core::channel::types::msgs::ChannelMsg;
                    match data {
                        ChannelMsg::OpenInit(data) => data.to_any(),
                        ChannelMsg::OpenTry(data) => data.to_any(),
                        ChannelMsg::OpenAck(data) => data.to_any(),
                        ChannelMsg::OpenConfirm(data) => data.to_any(),
                        ChannelMsg::CloseInit(data) => data.to_any(),
                        ChannelMsg::CloseConfirm(data) => data.to_any(),
                    }
                }
                MsgEnvelope::Packet(data) => {
                    use namada_sdk::ibc::core::channel::types::msgs::PacketMsg;
                    match data {
                        PacketMsg::Recv(data) => data.to_any(),
                        PacketMsg::Ack(data) => data.to_any(),
                        PacketMsg::Timeout(data) => data.to_any(),
                        PacketMsg::TimeoutOnClose(data) => data.to_any(),
                    }
                }
            };
            let mut bytes = vec![];
            proto_data.encode(&mut bytes).unwrap();
            tx.set_data(tx::Data::new(bytes));
        }
        IbcData::MsgTransfer(data) => {
            let mut bytes = vec![];
            data.to_any().encode(&mut bytes).unwrap();
            tx.set_data(tx::Data::new(bytes));
        }
        IbcData::MsgNftTransfer(data) => {
            let mut bytes = vec![];
            data.to_any().encode(&mut bytes).unwrap();
            tx.set_data(tx::Data::new(bytes));
        }
        IbcData::BorshMsgTransfer(data) => {
            tx.add_data(data);
        }
        IbcData::BorshMsgNftTransfer(data) => {
            tx.add_data(data);
        }
    }
}

#[derive(Arbitrary, Debug)]
struct NonEmptyVec<T> {
    // `vec` may be empty
    vec: Vec<T>,
    // there's always at least one element
    last: T,
}

impl<T> NonEmptyVec<T> {
    fn into_vec(self) -> Vec<T> {
        let NonEmptyVec { mut vec, last } = self;
        vec.push(last);
        vec
    }
}
