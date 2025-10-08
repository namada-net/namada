use std::cell::RefCell;
use std::collections::BTreeSet;
use std::ops::Deref;
use std::rc::Rc;
use std::str::FromStr;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use masp_primitives::sapling::Node;
use masp_primitives::sapling::redjubjub::PublicKey;
use masp_primitives::transaction::TransactionData;
use masp_primitives::transaction::sighash::{SignableInput, signature_hash};
use masp_primitives::transaction::txid::TxIdDigester;
use masp_primitives::zip32::ExtendedSpendingKey;
use masp_proofs::group::GroupEncoding;
use masp_proofs::sapling::BatchValidator;
use namada_apps_lib::address::{self, Address, InternalAddress};
use namada_apps_lib::collections::HashMap;
use namada_apps_lib::eth_bridge::read_native_erc20_address;
use namada_apps_lib::eth_bridge::storage::eth_bridge_queries::is_bridge_comptime_enabled;
use namada_apps_lib::eth_bridge::storage::whitelist;
use namada_apps_lib::eth_bridge_pool::{GasFee, PendingTransfer};
use namada_apps_lib::gas::{GasMeterKind, TxGasMeter, VpGasMeter};
use namada_apps_lib::governance::pgf::storage::steward::StewardDetail;
use namada_apps_lib::governance::storage::proposal::ProposalType;
use namada_apps_lib::governance::storage::vote::ProposalVote;
use namada_apps_lib::governance::{InitProposalData, VoteProposalData};
use namada_apps_lib::ibc::context::middlewares::create_transfer_middlewares;
use namada_apps_lib::ibc::core::channel::types::Version as ChannelVersion;
use namada_apps_lib::ibc::core::channel::types::channel::Order;
use namada_apps_lib::ibc::core::channel::types::msgs::MsgChannelOpenInit;
use namada_apps_lib::ibc::core::commitment_types::commitment::CommitmentPrefix;
use namada_apps_lib::ibc::core::connection::types::Counterparty;
use namada_apps_lib::ibc::core::connection::types::msgs::MsgConnectionOpenInit;
use namada_apps_lib::ibc::core::connection::types::version::Version;
use namada_apps_lib::ibc::core::host::types::identifiers::{
    ClientId, ConnectionId, PortId,
};
use namada_apps_lib::ibc::primitives::ToProto;
use namada_apps_lib::ibc::{COMMITMENT_PREFIX, IbcActions, NftTransferModule};
use namada_apps_lib::masp_primitives::merkle_tree::CommitmentTree;
use namada_apps_lib::masp_primitives::transaction::Transaction;
use namada_apps_lib::masp_proofs::sapling::SaplingVerificationContextInner;
use namada_apps_lib::proof_of_stake::KeySeg;
use namada_apps_lib::state::{Epoch, StorageRead, StorageWrite, TxIndex};
use namada_apps_lib::token::masp::{
    PVKs, partial_deauthorize, preload_verifying_keys,
};
use namada_apps_lib::token::{Amount, Transfer};
use namada_apps_lib::tx::{BatchedTx, Code, Section, Tx};
use namada_apps_lib::validation::{
    EthBridgeNutVp, EthBridgePoolVp, EthBridgeVp, GovernanceVp, IbcVp,
    IbcVpContext, MaspVp, MultitokenVp, ParametersVp, PgfVp, PosVp,
};
use namada_apps_lib::wallet::defaults;
use namada_apps_lib::{
    TransferSource, TransferTarget, governance, parameters, proof_of_stake,
    storage, token,
};
use namada_node::bench_utils::{
    ALBERT_PAYMENT_ADDRESS, ALBERT_SPENDING_KEY, BERTHA_PAYMENT_ADDRESS,
    BenchShell, BenchShieldedCtx, TX_BRIDGE_POOL_WASM, TX_IBC_WASM,
    TX_INIT_PROPOSAL_WASM, TX_RESIGN_STEWARD, TX_TRANSFER_WASM,
    TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL_WASM,
    generate_foreign_key_tx,
};
use namada_vm::wasm::VpCache;
use namada_vm::wasm::run::VpEvalWasm;
use namada_vp::native_vp::{self, NativeVp};
use rand::thread_rng;
use rand_core::OsRng;

type Ctx<'ctx, S, D, H, CA> =
    native_vp::Ctx<'ctx, S, VpCache<CA>, VpEvalWasm<D, H, CA>>;

fn governance(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_governance");

    for bench_name in [
        "foreign_key_write",
        "delegator_vote",
        "validator_vote",
        "minimal_proposal",
        "complete_proposal",
    ] {
        let bench_shell = BenchShell::default();
        let mut shell = bench_shell.write();

        let signed_tx = match bench_name {
            "foreign_key_write" => {
                generate_foreign_key_tx(&defaults::albert_keypair())
            }
            "delegator_vote" => {
                // Advance to the proposal voting period
                shell.advance_epoch();
                shell.generate_tx(
                    TX_VOTE_PROPOSAL_WASM,
                    VoteProposalData {
                        id: 0,
                        vote: ProposalVote::Yay,
                        voter: defaults::albert_address(),
                    },
                    None,
                    None,
                    vec![&defaults::albert_keypair()],
                )
            }
            "validator_vote" => {
                // Advance to the proposal voting period
                shell.advance_epoch();
                shell.generate_tx(
                    TX_VOTE_PROPOSAL_WASM,
                    VoteProposalData {
                        id: 0,
                        vote: ProposalVote::Nay,
                        voter: defaults::validator_address(),
                    },
                    None,
                    None,
                    vec![&defaults::albert_keypair()],
                )
            }
            "minimal_proposal" => {
                let content_section =
                    Section::ExtraData(Code::new(vec![], None));
                let params = proof_of_stake::storage::read_pos_params::<
                    _,
                    governance::Store<_>,
                >(&shell.state)
                .unwrap();
                let voting_start_epoch =
                    Epoch(2 + params.pipeline_len + params.unbonding_len);
                // Must start after current epoch
                debug_assert_eq!(
                    shell.state.get_block_epoch().unwrap().next(),
                    voting_start_epoch
                );
                shell.generate_tx(
                    TX_INIT_PROPOSAL_WASM,
                    InitProposalData {
                        content: content_section.get_hash(),
                        author: defaults::albert_address(),
                        r#type: ProposalType::Default,
                        voting_start_epoch,
                        voting_end_epoch: voting_start_epoch
                            .unchecked_add(3_u64),
                        activation_epoch: voting_start_epoch
                            .unchecked_add(9_u64),
                    },
                    None,
                    Some(vec![content_section]),
                    vec![&defaults::albert_keypair()],
                )
            }
            "complete_proposal" => {
                let max_code_size_key =
                    governance::storage::keys::get_max_proposal_code_size_key();
                let max_proposal_content_key =
                    governance::storage::keys::get_max_proposal_content_key();
                let max_code_size: u64 = shell
                    .state
                    .read(&max_code_size_key)
                    .expect("Error while reading from storage")
                    .expect("Missing max_code_size parameter in storage");
                let max_proposal_content_size: u64 = shell
                    .state
                    .read(&max_proposal_content_key)
                    .expect("Error while reading from storage")
                    .expect(
                        "Missing max_proposal_content parameter in storage",
                    );
                let content_section = Section::ExtraData(Code::new(
                    vec![0; max_proposal_content_size as _],
                    None,
                ));
                let wasm_code_section = Section::ExtraData(Code::new(
                    vec![0; max_code_size as _],
                    None,
                ));

                let params = proof_of_stake::storage::read_pos_params::<
                    _,
                    governance::Store<_>,
                >(&shell.state)
                .unwrap();
                let voting_start_epoch =
                    Epoch(2 + params.pipeline_len + params.unbonding_len);
                // Must start after current epoch
                debug_assert_eq!(
                    shell.state.get_block_epoch().unwrap().next(),
                    voting_start_epoch
                );
                shell.generate_tx(
                    TX_INIT_PROPOSAL_WASM,
                    InitProposalData {
                        content: content_section.get_hash(),
                        author: defaults::albert_address(),
                        r#type: ProposalType::DefaultWithWasm(
                            wasm_code_section.get_hash(),
                        ),
                        voting_start_epoch,
                        voting_end_epoch: voting_start_epoch
                            .unchecked_add(3_u64),
                        activation_epoch: voting_start_epoch
                            .unchecked_add(9_u64),
                    },
                    None,
                    Some(vec![content_section, wasm_code_section]),
                    vec![&defaults::albert_keypair()],
                )
            }
            _ => panic!("Unexpected bench test"),
        };

        // Run the tx to validate
        let verifiers_from_tx = shell.execute_tx(&signed_tx.to_ref());

        let (verifiers, keys_changed) = shell
            .state
            .write_log()
            .verifiers_and_changed_keys(&verifiers_from_tx);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = Ctx::new(
            &Address::Internal(InternalAddress::Governance),
            &shell.state,
            &signed_tx.tx,
            &signed_tx.cmt,
            &TxIndex(0),
            &gas_meter,
            &keys_changed,
            &verifiers,
            shell.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        );

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    GovernanceVp::validate_tx(
                        &ctx,
                        &signed_tx.to_ref(),
                        ctx.keys_changed,
                        ctx.verifiers,
                    )
                    .is_ok()
                )
            })
        });
    }

    group.finish();
}

// TODO(namada#2984): uncomment when SlashFund internal
// address is brought back
//
// fn slash_fund(c: &mut Criterion) {
//      let mut group = c.benchmark_group("vp_slash_fund");

//      // Write a random key under a foreign subspace
//      let foreign_key_write =
//          generate_foreign_key_tx(&defaults::albert_keypair());

//      let content_section = Section::ExtraData(Code::new(vec![]));
//      let governance_proposal = shell.generate_tx(
//          TX_INIT_PROPOSAL_WASM,
//          InitProposalData {
//              id: 0,
//              content: content_section.get_hash(),
//              author: defaults::albert_address(),
//              r#type: ProposalType::Default(None),
//              voting_start_epoch: 12.into(),
//              voting_end_epoch: 15.into(),
//              activation_epoch: 18.into(),
//          },
//          None,
//          Some(vec![content_section]),
//          Some(&defaults::albert_keypair()),
//      );

//      for (tx, bench_name) in [foreign_key_write, governance_proposal]
//          .into_iter()
//          .zip(["foreign_key_write", "governance_proposal"])
//      {
//          let mut shell = BenchShell::default();

//          // Run the tx to validate
//          let verifiers_from_tx = shell.execute_tx(&tx);

//          let (verifiers, keys_changed) = shell
//              .state
//              .write_log
//              .verifiers_and_changed_keys(&verifiers_from_tx);

//          let slash_fund = SlashFundVp {
//              ctx: Ctx::new(
//                  &Address::Internal(InternalAddress::SlashFund),
//                  &shell.state.storage,
//                  &shell.state.write_log,
//                  &tx,
//                  &TxIndex(0),
//
// VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
// u64::MAX.into(),                  )),
//                  &keys_changed,
//                  &verifiers,
//                  shell.vp_wasm_cache.clone(),
//              ),
//          };

//          group.bench_function(bench_name, |b| {
//              b.iter(|| {
//                  assert!(
//                      slash_fund
//                          .validate_tx(
//                              &tx,
//                              slash_fund.ctx.keys_changed,
//                              slash_fund.ctx.verifiers,
//                          )
//                          .unwrap()
//                  )
//              })
//          });
//      }

//      group.finish();
//  }

fn prepare_ibc_tx_and_ctx(bench_name: &str) -> (BenchShieldedCtx, BatchedTx) {
    match bench_name {
        "open_connection" => {
            let shielded_ctx = BenchShieldedCtx::default();
            let _ = shielded_ctx.shell.write().init_ibc_client_state(
                storage::Key::from(
                    Address::Internal(InternalAddress::Ibc).to_db_key(),
                ),
            );
            let msg = MsgConnectionOpenInit {
                client_id_on_a: ClientId::new("07-tendermint", 1).unwrap(),
                counterparty: Counterparty::new(
                    ClientId::from_str("07-tendermint-1").unwrap(),
                    None,
                    CommitmentPrefix::from(
                        COMMITMENT_PREFIX.as_bytes().to_vec(),
                    ),
                ),
                version: Some(Version::compatibles().first().unwrap().clone()),
                delay_period: std::time::Duration::new(100, 0),
                signer: defaults::albert_address().to_string().into(),
            };
            let mut data = vec![];
            prost::Message::encode(&msg.to_any(), &mut data).unwrap();
            let open_connection =
                shielded_ctx.shell.read().generate_ibc_tx(TX_IBC_WASM, data);

            (shielded_ctx, open_connection)
        }
        "open_channel" => {
            let shielded_ctx = BenchShieldedCtx::default();
            let _ = shielded_ctx.shell.write().init_ibc_connection();
            // Channel handshake
            let msg = MsgChannelOpenInit {
                port_id_on_a: PortId::transfer(),
                connection_hops_on_a: vec![ConnectionId::new(1)],
                port_id_on_b: PortId::transfer(),
                ordering: Order::Unordered,
                signer: defaults::albert_address().to_string().into(),
                version_proposal: ChannelVersion::new("ics20-1".to_string()),
            };

            // Avoid serializing the data again with borsh
            let mut data = vec![];
            prost::Message::encode(&msg.to_any(), &mut data).unwrap();
            let open_channel =
                shielded_ctx.shell.read().generate_ibc_tx(TX_IBC_WASM, data);

            (shielded_ctx, open_channel)
        }
        "outgoing_transfer" => {
            let shielded_ctx = BenchShieldedCtx::default();
            shielded_ctx.shell.write().init_ibc_channel();
            shielded_ctx.shell.write().enable_ibc_transfer();
            let outgoing_transfer =
                shielded_ctx.shell.read().generate_ibc_transfer_tx();

            (shielded_ctx, outgoing_transfer)
        }
        "outgoing_shielded_action" => {
            let mut shielded_ctx = BenchShieldedCtx::default();
            shielded_ctx.shell.write().init_ibc_channel();
            shielded_ctx.shell.write().enable_ibc_transfer();

            let albert_payment_addr = shielded_ctx
                .wallet
                .find_payment_addr(ALBERT_PAYMENT_ADDRESS)
                .unwrap()
                .to_owned();
            let albert_spending_key = shielded_ctx
                .wallet
                .find_spending_key(ALBERT_SPENDING_KEY, None)
                .unwrap()
                .to_owned();
            // Shield some tokens for Albert
            let (shielded_ctx, shield_tx) = shielded_ctx.generate_masp_tx(
                Amount::native_whole(500),
                TransferSource::Address(defaults::albert_address()),
                TransferTarget::PaymentAddress(albert_payment_addr),
            );
            shielded_ctx.shell.write().execute_tx(&shield_tx.to_ref());
            shielded_ctx.shell.write().commit_masp_tx(shield_tx.tx);
            shielded_ctx.shell.write().commit_block();
            shielded_ctx.generate_shielded_action(
                Amount::native_whole(10),
                TransferSource::ExtendedKey(
                    ExtendedSpendingKey::from(albert_spending_key).into(),
                ),
                defaults::bertha_address().to_string(),
            )
        }
        _ => panic!("Unexpected bench test"),
    }
}

fn ibc(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_ibc");

    // NOTE: Ibc encompass a variety of different messages that can be executed,
    // here we only benchmark a few of those Connection handshake

    for bench_name in [
        "open_connection",
        "open_channel",
        "outgoing_transfer",
        "outgoing_shielded_action",
    ] {
        // Initialize the state according to the target tx
        let (shielded_ctx, signed_tx) = prepare_ibc_tx_and_ctx(bench_name);

        let verifiers_from_tx =
            shielded_ctx.shell.write().execute_tx(&signed_tx.to_ref());
        let (verifiers, keys_changed) = shielded_ctx
            .shell
            .read()
            .state
            .write_log()
            .verifiers_and_changed_keys(&verifiers_from_tx);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let shell_read = shielded_ctx.shell.read();
        let ibc = IbcVp::new(Ctx::new(
            &Address::Internal(InternalAddress::Ibc),
            &shell_read.state,
            &signed_tx.tx,
            &signed_tx.cmt,
            &TxIndex(0),
            &gas_meter,
            &keys_changed,
            &verifiers,
            shell_read.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        ));

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    ibc.validate_tx(
                        &signed_tx.to_ref(),
                        ibc.ctx.keys_changed,
                        ibc.ctx.verifiers,
                    )
                    .is_ok()
                )
            })
        });
    }

    group.finish();
}

fn vp_multitoken(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_multitoken");
    let bench_shell = BenchShell::default();
    let shell = bench_shell.read();

    let foreign_key_write =
        generate_foreign_key_tx(&defaults::albert_keypair());

    let transfer = shell.generate_tx(
        TX_TRANSFER_WASM,
        Transfer::default()
            .transfer(
                defaults::albert_address(),
                defaults::bertha_address(),
                address::testing::nam(),
                Amount::native_whole(1000).native_denominated(),
            )
            .unwrap(),
        None,
        None,
        vec![&defaults::albert_keypair()],
    );

    for (signed_tx, bench_name) in [foreign_key_write, transfer]
        .iter()
        .zip(["foreign_key_write", "transfer"])
    {
        let bench_shell = BenchShell::default();
        let mut shell = bench_shell.write();
        let verifiers_from_tx = shell.execute_tx(&signed_tx.to_ref());
        let (verifiers, keys_changed) = shell
            .state
            .write_log()
            .verifiers_and_changed_keys(&verifiers_from_tx);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = Ctx::new(
            &Address::Internal(InternalAddress::Multitoken),
            &shell.state,
            &signed_tx.tx,
            &signed_tx.cmt,
            &TxIndex(0),
            &gas_meter,
            &keys_changed,
            &verifiers,
            shell.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        );

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    MultitokenVp::validate_tx(
                        &ctx,
                        &signed_tx.to_ref(),
                        ctx.keys_changed,
                        ctx.verifiers,
                    )
                    .is_ok()
                )
            })
        });
    }
}

// Generate and run masp transaction to be verified. Returns the verifier set
// from tx and the tx.
fn setup_storage_for_masp_verification(
    bench_name: &str,
) -> (BenchShieldedCtx, BTreeSet<Address>, BatchedTx) {
    let amount = Amount::native_whole(500);
    let mut shielded_ctx = BenchShieldedCtx::default();

    let albert_spending_key = shielded_ctx
        .wallet
        .find_spending_key(ALBERT_SPENDING_KEY, None)
        .unwrap()
        .to_owned();
    let albert_payment_addr = shielded_ctx
        .wallet
        .find_payment_addr(ALBERT_PAYMENT_ADDRESS)
        .unwrap()
        .to_owned();
    let bertha_payment_addr = shielded_ctx
        .wallet
        .find_payment_addr(BERTHA_PAYMENT_ADDRESS)
        .unwrap()
        .to_owned();

    // Shield some tokens for Albert
    let (shielded_ctx, shield_tx) = shielded_ctx.generate_masp_tx(
        amount,
        TransferSource::Address(defaults::albert_address()),
        TransferTarget::PaymentAddress(albert_payment_addr),
    );

    // Adjust the state of the MASP to reflect the transaction's changes
    {
        let mut write_lock = shielded_ctx.shell.write();
        write_lock.execute_tx(&shield_tx.to_ref());
        write_lock.commit_masp_tx(shield_tx.tx);

        // Update the anchor in storage
        let tree_key = token::storage_key::masp_commitment_tree_key();
        let updated_tree: CommitmentTree<Node> =
            write_lock.state.read(&tree_key).unwrap().unwrap();
        let anchor_key =
            token::storage_key::masp_commitment_anchor_key(updated_tree.root());
        write_lock.state.write(&anchor_key, ()).unwrap();
        write_lock.commit_block();

        // Advance the masp epoch to generate rewards
        for _ in 0..2 {
            write_lock.advance_epoch();
        }
    }

    let (shielded_ctx, signed_tx) = match bench_name {
        "shielding" => shielded_ctx.generate_masp_tx(
            amount,
            TransferSource::Address(defaults::albert_address()),
            TransferTarget::PaymentAddress(albert_payment_addr),
        ),
        "unshielding" => shielded_ctx.generate_masp_tx(
            amount,
            TransferSource::ExtendedKey(
                ExtendedSpendingKey::from(albert_spending_key).into(),
            ),
            TransferTarget::Address(defaults::albert_address()),
        ),
        "shielded" => shielded_ctx.generate_masp_tx(
            amount,
            TransferSource::ExtendedKey(
                ExtendedSpendingKey::from(albert_spending_key).into(),
            ),
            TransferTarget::PaymentAddress(bertha_payment_addr),
        ),
        _ => panic!("Unexpected bench test"),
    };
    let verifiers_from_tx =
        shielded_ctx.shell.write().execute_tx(&signed_tx.to_ref());

    (shielded_ctx, verifiers_from_tx, signed_tx)
}

fn masp(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_masp");

    for bench_name in ["shielding", "unshielding", "shielded"] {
        group.bench_function(bench_name, |b| {
            let (shielded_ctx, verifiers_from_tx, signed_tx) =
                setup_storage_for_masp_verification(bench_name);
            let shell_read = shielded_ctx.shell.read();
            let (verifiers, keys_changed) = shell_read
                .state
                .write_log()
                .verifiers_and_changed_keys(&verifiers_from_tx);

            let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
                &TxGasMeter::new(u64::MAX, 1),
            ));
            let ctx = Ctx::new(
                &Address::Internal(InternalAddress::Masp),
                &shell_read.state,
                &signed_tx.tx,
                &signed_tx.cmt,
                &TxIndex(0),
                &gas_meter,
                &keys_changed,
                &verifiers,
                shell_read.vp_wasm_cache.clone(),
                GasMeterKind::MutGlobal,
            );

            b.iter(|| {
                assert!(
                    MaspVp::validate_tx(
                        &ctx,
                        &signed_tx.to_ref(),
                        ctx.keys_changed,
                        ctx.verifiers,
                    )
                    .is_ok()
                );
            })
        });
    }

    group.finish();
}

// Instead of benchmarking BatchValidator::check_bundle we benchmark the 4
// functions that are called internally for better resolution
fn masp_check_spend(c: &mut Criterion) {
    c.bench_function("vp_masp_check_spend", |b| {
        b.iter_batched(
            || {
                let (_, _verifiers_from_tx, signed_tx) =
                    setup_storage_for_masp_verification("shielded");

                let transaction = signed_tx
                    .tx
                    .sections
                    .into_iter()
                    .filter_map(|section| match section {
                        Section::MaspTx(transaction) => Some(transaction),
                        _ => None,
                    })
                    .collect::<Vec<Transaction>>()
                    .first()
                    .unwrap()
                    .to_owned();
                let spend = transaction
                    .sapling_bundle()
                    .unwrap()
                    .shielded_spends
                    .first()
                    .unwrap()
                    .to_owned();
                let ctx = SaplingVerificationContextInner::new();
                let tx_data = transaction.deref();
                // Partially deauthorize the transparent bundle
                let unauth_tx_data = partial_deauthorize(tx_data).unwrap();
                let txid_parts = unauth_tx_data.digest(TxIdDigester);
                let sighash = signature_hash(
                    &unauth_tx_data,
                    &SignableInput::Shielded,
                    &txid_parts,
                );
                let zkproof = masp_proofs::bellman::groth16::Proof::read(
                    spend.zkproof.as_slice(),
                )
                .unwrap();

                (ctx, spend, sighash, zkproof)
            },
            |(mut ctx, spend, sighash, zkproof)| {
                assert!(ctx.check_spend(
                    spend.cv,
                    spend.anchor,
                    &spend.nullifier.0,
                    PublicKey(spend.rk.0),
                    sighash.as_ref(),
                    spend.spend_auth_sig,
                    zkproof,
                    &mut (),
                    // We do sig and proofs verification in parallel, so just
                    // use dummy verifiers here
                    |_, _, _, _| true,
                    |_, _, _| true
                ));
            },
            BatchSize::SmallInput,
        )
    });
}

fn masp_check_convert(c: &mut Criterion) {
    c.bench_function("vp_masp_check_convert", |b| {
        b.iter_batched(
            || {
                let (_, _verifiers_from_tx, signed_tx) =
                    setup_storage_for_masp_verification("shielded");

                let transaction = signed_tx
                    .tx
                    .sections
                    .into_iter()
                    .filter_map(|section| match section {
                        Section::MaspTx(transaction) => Some(transaction),
                        _ => None,
                    })
                    .collect::<Vec<Transaction>>()
                    .first()
                    .unwrap()
                    .to_owned();
                let convert = transaction
                    .sapling_bundle()
                    .unwrap()
                    .shielded_converts
                    .first()
                    .unwrap()
                    .to_owned();
                let ctx = SaplingVerificationContextInner::new();
                let zkproof = masp_proofs::bellman::groth16::Proof::read(
                    convert.zkproof.as_slice(),
                )
                .unwrap();

                (ctx, convert, zkproof)
            },
            |(mut ctx, convert, zkproof)| {
                assert!(ctx.check_convert(
                    convert.cv,
                    convert.anchor,
                    zkproof,
                    &mut (),
                    // We do proofs verification in parallel, so just use dummy
                    // verifier here
                    |_, _, _| true,
                ));
            },
            BatchSize::SmallInput,
        )
    });
}

fn masp_check_output(c: &mut Criterion) {
    c.bench_function("vp_masp_check_output", |b| {
        b.iter_batched(
            || {
                let (_, _verifiers_from_tx, signed_tx) =
                    setup_storage_for_masp_verification("shielded");

                let transaction = signed_tx
                    .tx
                    .sections
                    .into_iter()
                    .filter_map(|section| match section {
                        Section::MaspTx(transaction) => Some(transaction),
                        _ => None,
                    })
                    .collect::<Vec<Transaction>>()
                    .first()
                    .unwrap()
                    .to_owned();
                let output = transaction
                    .sapling_bundle()
                    .unwrap()
                    .shielded_outputs
                    .first()
                    .unwrap()
                    .to_owned();
                let ctx = SaplingVerificationContextInner::new();
                let zkproof = masp_proofs::bellman::groth16::Proof::read(
                    output.zkproof.as_slice(),
                )
                .unwrap();
                let epk = masp_proofs::jubjub::ExtendedPoint::from_bytes(
                    &output.ephemeral_key.0,
                )
                .unwrap();

                (ctx, output, epk, zkproof)
            },
            |(mut ctx, output, epk, zkproof)| {
                assert!(ctx.check_output(
                    output.cv,
                    output.cmu,
                    epk,
                    zkproof,
                    // We do proofs verification in parallel, so just use dummy
                    // verifier here
                    |_, _| true
                ));
            },
            BatchSize::SmallInput,
        )
    });
}

fn masp_final_check(c: &mut Criterion) {
    let (_, _verifiers_from_tx, signed_tx) =
        setup_storage_for_masp_verification("shielded");

    let transaction = signed_tx
        .tx
        .sections
        .into_iter()
        .filter_map(|section| match section {
            Section::MaspTx(transaction) => Some(transaction),
            _ => None,
        })
        .collect::<Vec<Transaction>>()
        .first()
        .unwrap()
        .to_owned();
    let sapling_bundle = transaction.sapling_bundle().unwrap();
    // Partially deauthorize the transparent bundle
    let unauth_tx_data = partial_deauthorize(transaction.deref()).unwrap();
    let txid_parts = unauth_tx_data.digest(TxIdDigester);
    let sighash =
        signature_hash(&unauth_tx_data, &SignableInput::Shielded, &txid_parts);
    let mut ctx = SaplingVerificationContextInner::new();

    // Check spends, converts and outputs before the final check
    assert!(sapling_bundle.shielded_spends.iter().all(|spend| {
        let zkproof = masp_proofs::bellman::groth16::Proof::read(
            spend.zkproof.as_slice(),
        )
        .unwrap();

        ctx.check_spend(
            spend.cv,
            spend.anchor,
            &spend.nullifier.0,
            PublicKey(spend.rk.0),
            sighash.as_ref(),
            spend.spend_auth_sig,
            zkproof,
            &mut (),
            |_, _, _, _| true,
            |_, _, _| true,
        )
    }));
    assert!(sapling_bundle.shielded_converts.iter().all(|convert| {
        let zkproof = masp_proofs::bellman::groth16::Proof::read(
            convert.zkproof.as_slice(),
        )
        .unwrap();
        ctx.check_convert(
            convert.cv,
            convert.anchor,
            zkproof,
            &mut (),
            |_, _, _| true,
        )
    }));
    assert!(sapling_bundle.shielded_outputs.iter().all(|output| {
        let zkproof = masp_proofs::bellman::groth16::Proof::read(
            output.zkproof.as_slice(),
        )
        .unwrap();
        let epk = masp_proofs::jubjub::ExtendedPoint::from_bytes(
            &output.ephemeral_key.0,
        )
        .unwrap();
        ctx.check_output(
            output.cv,
            output.cmu,
            epk.to_owned(),
            zkproof,
            |_, _| true,
        )
    }));

    c.bench_function("vp_masp_final_check", |b| {
        b.iter(|| {
            assert!(ctx.final_check(
                sapling_bundle.value_balance.clone(),
                sighash.as_ref(),
                sapling_bundle.authorization.binding_sig,
                // We do sig verification in parallel, so just use dummy
                // verifier here
                |_, _, _| true
            ))
        })
    });
}

#[derive(Debug)]
enum BenchNote {
    Spend,
    Convert,
    Output,
}

// Tweaks the transaction to match the desired benchmark
fn customize_masp_tx_data(
    multi: bool,
    request: &BenchNote,
) -> (
    TransactionData<masp_primitives::transaction::Authorized>,
    Transaction,
) {
    let (_, _, tx) = setup_storage_for_masp_verification("unshielding");
    let transaction = tx
        .tx
        .sections
        .into_iter()
        .filter_map(|section| match section {
            Section::MaspTx(transaction) => Some(transaction),
            _ => None,
        })
        .collect::<Vec<Transaction>>()
        .first()
        .unwrap()
        .to_owned();
    let mut sapling_bundle = transaction.sapling_bundle().unwrap().to_owned();

    match request {
        BenchNote::Spend => {
            if multi {
                // ensure we have two spend proofs
                sapling_bundle.shielded_spends = [
                    sapling_bundle.shielded_spends.clone(),
                    sapling_bundle.shielded_spends,
                ]
                .concat();
                assert_eq!(sapling_bundle.shielded_spends.len(), 2);
            } else {
                // ensure we have one spend proof
                assert_eq!(sapling_bundle.shielded_spends.len(), 1);
            }
        }
        BenchNote::Convert => {
            if multi {
                // ensure we have two convert proofs
                sapling_bundle.shielded_converts = [
                    sapling_bundle.shielded_converts.clone(),
                    sapling_bundle.shielded_converts,
                ]
                .concat();
                assert_eq!(sapling_bundle.shielded_converts.len(), 2);
            } else {
                // ensure we have one convert proof
                assert_eq!(sapling_bundle.shielded_converts.len(), 1);
            }
        }
        BenchNote::Output => {
            if multi {
                // ensure we have two output proofs
                assert_eq!(sapling_bundle.shielded_outputs.len(), 2);
            } else {
                // ensure we have one output proof
                sapling_bundle.shielded_outputs.truncate(1);
                assert_eq!(sapling_bundle.shielded_outputs.len(), 1);
            }
        }
    };

    (
        TransactionData::from_parts(
            transaction.version(),
            transaction.consensus_branch_id(),
            transaction.lock_time(),
            transaction.expiry_height(),
            transaction.transparent_bundle().cloned(),
            Some(sapling_bundle),
        ),
        transaction,
    )
}

// Benchmark the cost of validating two signatures in a batch (two leverage
// multiscalar multiplication speedups). The gas cost per single signature
// verification should be the result of this bench divided by two.
fn masp_batch_signature_verification(c: &mut Criterion) {
    let (_, _, tx) = setup_storage_for_masp_verification("unshielding");
    let transaction = tx
        .tx
        .sections
        .into_iter()
        .filter_map(|section| match section {
            Section::MaspTx(transaction) => Some(transaction),
            _ => None,
        })
        .collect::<Vec<Transaction>>()
        .first()
        .unwrap()
        .to_owned();
    let sapling_bundle = transaction.sapling_bundle().unwrap();
    // ensure we have two signatures to verify (the binding and one spending)
    assert_eq!(sapling_bundle.shielded_spends.len(), 1);

    // Partially deauthorize the transparent bundle
    let unauth_tx_data = partial_deauthorize(transaction.deref()).unwrap();
    let txid_parts = unauth_tx_data.digest(TxIdDigester);
    let sighash =
        signature_hash(&unauth_tx_data, &SignableInput::Shielded, &txid_parts)
            .as_ref()
            .to_owned();

    c.bench_function("masp_batch_signature_verification", |b| {
        b.iter_batched(
            || {
                let mut ctx = BatchValidator::new();
                // Check bundle first
                if !ctx.check_bundle(sapling_bundle.to_owned(), sighash) {
                    panic!("Failed check bundle");
                }

                ctx
            },
            |ctx| assert!(ctx.verify_signatures(OsRng).is_ok()),
            BatchSize::SmallInput,
        )
    });
}

// Benchmark both one and two proofs and take the difference as the variable
// cost for every proofs. Charge the full cost for the first note and then
// charge the variable cost multiplied by the number of remaining notes
fn masp_batch_spend_proofs_validate(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("masp_batch_spend_proofs_validate");
    let PVKs { spend_vk, .. } = preload_verifying_keys();

    for double in [true, false] {
        let (tx_data, transaction) =
            customize_masp_tx_data(double, &BenchNote::Spend);

        // Partially deauthorize the transparent bundle
        let unauth_tx_data = partial_deauthorize(transaction.deref()).unwrap();
        let txid_parts = unauth_tx_data.digest(TxIdDigester);
        // Compute the sighash from the original, unmodified transaction
        let sighash = signature_hash(
            &unauth_tx_data,
            &SignableInput::Shielded,
            &txid_parts,
        )
        .as_ref()
        .to_owned();
        let sapling_bundle = tx_data.sapling_bundle().unwrap();

        let bench_name = if double { "double" } else { "single" };
        group.bench_function(bench_name, |b| {
            b.iter_batched(
                || {
                    let mut ctx = BatchValidator::new();
                    // Check bundle first
                    if !ctx.check_bundle(sapling_bundle.to_owned(), sighash) {
                        panic!("Failed check bundle");
                    }

                    ctx
                },
                |ctx| {
                    assert!(ctx.verify_spend_proofs(spend_vk, &mut rng).is_ok())
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

// Benchmark both one and two proofs and take the difference as the variable
// cost for every proofs. Charge the full cost for the first note and then
// charge the variable cost multiplied by the number of remaining notes
fn masp_batch_convert_proofs_validate(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("masp_batch_convert_proofs_validate");
    let PVKs { convert_vk, .. } = preload_verifying_keys();

    for double in [true, false] {
        let (tx_data, transaction) =
            customize_masp_tx_data(double, &BenchNote::Convert);

        // Partially deauthorize the transparent bundle
        let unauth_tx_data = partial_deauthorize(transaction.deref()).unwrap();
        let txid_parts = unauth_tx_data.digest(TxIdDigester);
        // Compute the sighash from the original, unmodified transaction
        let sighash = signature_hash(
            &unauth_tx_data,
            &SignableInput::Shielded,
            &txid_parts,
        )
        .as_ref()
        .to_owned();
        let sapling_bundle = tx_data.sapling_bundle().unwrap();

        let bench_name = if double { "double" } else { "single" };
        group.bench_function(bench_name, |b| {
            b.iter_batched(
                || {
                    let mut ctx = BatchValidator::new();
                    // Check bundle first
                    if !ctx.check_bundle(sapling_bundle.to_owned(), sighash) {
                        panic!("Failed check bundle");
                    }

                    ctx
                },
                |ctx| {
                    assert!(
                        ctx.verify_convert_proofs(convert_vk, &mut rng).is_ok()
                    )
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

// Benchmark both one and two proofs and take the difference as the variable
// cost for every proofs. Charge the full cost for the first note and then
// charge the variable cost multiplied by the number of remaining notes
fn masp_batch_output_proofs_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("masp_batch_output_proofs_validate");
    let PVKs { output_vk, .. } = preload_verifying_keys();
    let mut rng = thread_rng();

    for double in [true, false] {
        let (tx_data, transaction) =
            customize_masp_tx_data(double, &BenchNote::Output);

        // Partially deauthorize the transparent bundle
        let unauth_tx_data = partial_deauthorize(transaction.deref()).unwrap();
        let txid_parts = unauth_tx_data.digest(TxIdDigester);
        // Compute the sighash from the original, unmodified transaction
        let sighash = signature_hash(
            &unauth_tx_data,
            &SignableInput::Shielded,
            &txid_parts,
        )
        .as_ref()
        .to_owned();
        let sapling_bundle = tx_data.sapling_bundle().unwrap();

        let bench_name = if double { "double" } else { "single" };
        group.bench_function(bench_name, |b| {
            b.iter_batched(
                || {
                    let mut ctx = BatchValidator::new();
                    // Check bundle first
                    if !ctx.check_bundle(sapling_bundle.to_owned(), sighash) {
                        panic!("Failed check bundle");
                    }

                    ctx
                },
                |ctx| {
                    assert!(
                        ctx.verify_output_proofs(output_vk, &mut rng).is_ok()
                    )
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn pgf(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_pgf");

    for bench_name in [
        "foreign_key_write",
        "remove_steward",
        "steward_inflation_rate",
    ] {
        let bench_shell = BenchShell::default();
        let mut shell = bench_shell.write();
        namada_apps_lib::governance::pgf::storage::keys::stewards_handle()
            .insert(
                &mut shell.state,
                defaults::albert_address(),
                StewardDetail::base(defaults::albert_address()),
            )
            .unwrap();

        let signed_tx = match bench_name {
            "foreign_key_write" => {
                generate_foreign_key_tx(&defaults::albert_keypair())
            }
            "remove_steward" => shell.generate_tx(
                TX_RESIGN_STEWARD,
                defaults::albert_address(),
                None,
                None,
                vec![&defaults::albert_keypair()],
            ),
            "steward_inflation_rate" => {
                let data =
                    namada_apps_lib::tx::data::pgf::UpdateStewardCommission {
                        steward: defaults::albert_address(),
                        commission: HashMap::from([(
                            defaults::albert_address(),
                            namada_apps_lib::dec::Dec::zero(),
                        )]),
                    };
                shell.generate_tx(
                    TX_UPDATE_STEWARD_COMMISSION,
                    data,
                    None,
                    None,
                    vec![&defaults::albert_keypair()],
                )
            }
            _ => panic!("Unexpected bench test"),
        };

        // Run the tx to validate
        let verifiers_from_tx = shell.execute_tx(&signed_tx.to_ref());

        let (verifiers, keys_changed) = shell
            .state
            .write_log()
            .verifiers_and_changed_keys(&verifiers_from_tx);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = Ctx::new(
            &Address::Internal(InternalAddress::Pgf),
            &shell.state,
            &signed_tx.tx,
            &signed_tx.cmt,
            &TxIndex(0),
            &gas_meter,
            &keys_changed,
            &verifiers,
            shell.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        );

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    PgfVp::validate_tx(
                        &ctx,
                        &signed_tx.to_ref(),
                        ctx.keys_changed,
                        ctx.verifiers,
                    )
                    .is_ok()
                )
            })
        });
    }

    group.finish();
}

fn eth_bridge_nut(c: &mut Criterion) {
    if !is_bridge_comptime_enabled() {
        return;
    }

    let bench_shell = BenchShell::default();
    let mut shell = bench_shell.write();
    let native_erc20_addres = read_native_erc20_address(&shell.state).unwrap();

    let signed_tx = {
        let data = PendingTransfer {
            transfer: namada_apps_lib::eth_bridge_pool::TransferToEthereum {
                kind:
                    namada_apps_lib::eth_bridge_pool::TransferToEthereumKind::Erc20,
                asset: native_erc20_addres,
                recipient: namada_apps_lib::ethereum_events::EthAddress([1u8; 20]),
                sender: defaults::albert_address(),
                amount: Amount::from(1),
            },
            gas_fee: GasFee {
                amount: Amount::from(100),
                payer: defaults::albert_address(),
                token: shell.state.in_mem().native_token.clone(),
            },
        };
        shell.generate_tx(
            TX_BRIDGE_POOL_WASM,
            data,
            None,
            None,
            vec![&defaults::albert_keypair()],
        )
    };

    // Run the tx to validate
    let verifiers_from_tx = shell.execute_tx(&signed_tx.to_ref());

    let (verifiers, keys_changed) = shell
        .state
        .write_log()
        .verifiers_and_changed_keys(&verifiers_from_tx);

    let vp_address =
        Address::Internal(InternalAddress::Nut(native_erc20_addres));
    let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
        &TxGasMeter::new(u64::MAX, 1),
    ));
    let ctx = Ctx::new(
        &vp_address,
        &shell.state,
        &signed_tx.tx,
        &signed_tx.cmt,
        &TxIndex(0),
        &gas_meter,
        &keys_changed,
        &verifiers,
        shell.vp_wasm_cache.clone(),
        GasMeterKind::MutGlobal,
    );

    c.bench_function("vp_eth_bridge_nut", |b| {
        b.iter(|| {
            assert!(
                EthBridgeNutVp::validate_tx(
                    &ctx,
                    &signed_tx.to_ref(),
                    ctx.keys_changed,
                    ctx.verifiers,
                )
                .is_ok()
            )
        })
    });
}

fn eth_bridge(c: &mut Criterion) {
    if !is_bridge_comptime_enabled() {
        return;
    }

    let bench_shell = BenchShell::default();
    let mut shell = bench_shell.write();
    let native_erc20_addres = read_native_erc20_address(&shell.state).unwrap();

    let signed_tx = {
        let data = PendingTransfer {
            transfer: namada_apps_lib::eth_bridge_pool::TransferToEthereum {
                kind:
                    namada_apps_lib::eth_bridge_pool::TransferToEthereumKind::Erc20,
                asset: native_erc20_addres,
                recipient: namada_apps_lib::ethereum_events::EthAddress([1u8; 20]),
                sender: defaults::albert_address(),
                amount: Amount::from(1),
            },
            gas_fee: GasFee {
                amount: Amount::from(100),
                payer: defaults::albert_address(),
                token: shell.state.in_mem().native_token.clone(),
            },
        };
        shell.generate_tx(
            TX_BRIDGE_POOL_WASM,
            data,
            None,
            None,
            vec![&defaults::albert_keypair()],
        )
    };

    // Run the tx to validate
    let verifiers_from_tx = shell.execute_tx(&signed_tx.to_ref());

    let (verifiers, keys_changed) = shell
        .state
        .write_log()
        .verifiers_and_changed_keys(&verifiers_from_tx);

    let vp_address = Address::Internal(InternalAddress::EthBridge);
    let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
        &TxGasMeter::new(u64::MAX, 1),
    ));
    let ctx = Ctx::new(
        &vp_address,
        &shell.state,
        &signed_tx.tx,
        &signed_tx.cmt,
        &TxIndex(0),
        &gas_meter,
        &keys_changed,
        &verifiers,
        shell.vp_wasm_cache.clone(),
        GasMeterKind::MutGlobal,
    );

    c.bench_function("vp_eth_bridge", |b| {
        b.iter(|| {
            assert!(
                EthBridgeVp::validate_tx(
                    &ctx,
                    &signed_tx.to_ref(),
                    ctx.keys_changed,
                    ctx.verifiers,
                )
                .is_ok()
            )
        })
    });
}

fn eth_bridge_pool(c: &mut Criterion) {
    if !is_bridge_comptime_enabled() {
        return;
    }

    // NOTE: this vp is one of the most expensive but its cost comes from the
    // numerous accesses to storage that we already account for, so no need to
    // benchmark specific sections of it like for the ibc native vp
    let bench_shell = BenchShell::default();
    let mut shell = bench_shell.write();
    let native_erc20_addres = read_native_erc20_address(&shell.state).unwrap();

    // Whitelist NAM token
    let cap_key = whitelist::Key {
        asset: native_erc20_addres,
        suffix: whitelist::KeyType::Cap,
    }
    .into();
    shell.state.write(&cap_key, Amount::from(1_000)).unwrap();

    let whitelisted_key = whitelist::Key {
        asset: native_erc20_addres,
        suffix: whitelist::KeyType::Whitelisted,
    }
    .into();
    shell.state.write(&whitelisted_key, true).unwrap();

    let denom_key = whitelist::Key {
        asset: native_erc20_addres,
        suffix: whitelist::KeyType::Denomination,
    }
    .into();
    shell.state.write(&denom_key, 0).unwrap();

    let signed_tx = {
        let data = PendingTransfer {
            transfer: namada_apps_lib::eth_bridge_pool::TransferToEthereum {
                kind:
                    namada_apps_lib::eth_bridge_pool::TransferToEthereumKind::Erc20,
                asset: native_erc20_addres,
                recipient: namada_apps_lib::ethereum_events::EthAddress([1u8; 20]),
                sender: defaults::albert_address(),
                amount: Amount::from(1),
            },
            gas_fee: GasFee {
                amount: Amount::from(100),
                payer: defaults::albert_address(),
                token: shell.state.in_mem().native_token.clone(),
            },
        };
        shell.generate_tx(
            TX_BRIDGE_POOL_WASM,
            data,
            None,
            None,
            vec![&defaults::albert_keypair()],
        )
    };

    // Run the tx to validate
    let verifiers_from_tx = shell.execute_tx(&signed_tx.to_ref());

    let (verifiers, keys_changed) = shell
        .state
        .write_log()
        .verifiers_and_changed_keys(&verifiers_from_tx);

    let vp_address = Address::Internal(InternalAddress::EthBridgePool);
    let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
        &TxGasMeter::new(u64::MAX, 1),
    ));
    let ctx = Ctx::new(
        &vp_address,
        &shell.state,
        &signed_tx.tx,
        &signed_tx.cmt,
        &TxIndex(0),
        &gas_meter,
        &keys_changed,
        &verifiers,
        shell.vp_wasm_cache.clone(),
        GasMeterKind::MutGlobal,
    );

    c.bench_function("vp_eth_bridge_pool", |b| {
        b.iter(|| {
            assert!(
                EthBridgePoolVp::validate_tx(
                    &ctx,
                    &signed_tx.to_ref(),
                    ctx.keys_changed,
                    ctx.verifiers,
                )
                .is_ok()
            )
        })
    });
}

fn parameters(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_parameters");

    for bench_name in ["foreign_key_write", "parameter_change"] {
        let bench_shell = BenchShell::default();
        let mut shell = bench_shell.write();

        let (verifiers_from_tx, signed_tx) = match bench_name {
            "foreign_key_write" => {
                let tx = generate_foreign_key_tx(&defaults::albert_keypair());
                // Run the tx to validate
                let verifiers_from_tx = shell.execute_tx(&tx.to_ref());
                (verifiers_from_tx, tx)
            }
            "parameter_change" => {
                // Simulate governance proposal to modify a parameter
                let min_proposal_fund_key =
            namada_apps_lib::governance::storage::keys::get_min_proposal_fund_key();
                shell.state.write(&min_proposal_fund_key, 1_000).unwrap();

                let proposal_key = namada_apps_lib::governance::storage::keys::get_proposal_execution_key(0);
                shell.state.write(&proposal_key, 0).unwrap();

                // Return a dummy tx for validation
                let mut tx =
                    Tx::from_type(namada_apps_lib::tx::data::TxType::Raw);
                tx.set_data(namada_apps_lib::tx::Data::new(
                    borsh::to_vec(&0).unwrap(),
                ));
                let verifiers_from_tx = BTreeSet::default();
                let cmt = tx.first_commitments().unwrap().clone();
                let batched_tx = tx.batch_tx(cmt);
                (verifiers_from_tx, batched_tx)
            }
            _ => panic!("Unexpected bench test"),
        };

        let (verifiers, keys_changed) = shell
            .state
            .write_log()
            .verifiers_and_changed_keys(&verifiers_from_tx);

        let vp_address = Address::Internal(InternalAddress::Parameters);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = Ctx::new(
            &vp_address,
            &shell.state,
            &signed_tx.tx,
            &signed_tx.cmt,
            &TxIndex(0),
            &gas_meter,
            &keys_changed,
            &verifiers,
            shell.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        );

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    ParametersVp::validate_tx(
                        &ctx,
                        &signed_tx.to_ref(),
                        ctx.keys_changed,
                        ctx.verifiers,
                    )
                    .is_ok()
                )
            })
        });
    }

    group.finish();
}

fn pos(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_pos");

    for bench_name in ["foreign_key_write", "parameter_change"] {
        let bench_shell = BenchShell::default();
        let mut shell = bench_shell.write();

        let (verifiers_from_tx, signed_tx) = match bench_name {
            "foreign_key_write" => {
                let tx = generate_foreign_key_tx(&defaults::albert_keypair());
                // Run the tx to validate
                let verifiers_from_tx = shell.execute_tx(&tx.to_ref());
                (verifiers_from_tx, tx)
            }
            "parameter_change" => {
                // Simulate governance proposal to modify a parameter
                let min_proposal_fund_key =
            namada_apps_lib::governance::storage::keys::get_min_proposal_fund_key();
                shell.state.write(&min_proposal_fund_key, 1_000).unwrap();

                let proposal_key = namada_apps_lib::governance::storage::keys::get_proposal_execution_key(0);
                shell.state.write(&proposal_key, 0).unwrap();

                // Return a dummy tx for validation
                let mut tx =
                    Tx::from_type(namada_apps_lib::tx::data::TxType::Raw);
                tx.set_data(namada_apps_lib::tx::Data::new(
                    borsh::to_vec(&0).unwrap(),
                ));
                let verifiers_from_tx = BTreeSet::default();
                let cmt = tx.first_commitments().unwrap().clone();
                let batched_tx = tx.batch_tx(cmt);
                (verifiers_from_tx, batched_tx)
            }
            _ => panic!("Unexpected bench test"),
        };

        let (verifiers, keys_changed) = shell
            .state
            .write_log()
            .verifiers_and_changed_keys(&verifiers_from_tx);

        let vp_address = Address::Internal(InternalAddress::PoS);
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = Ctx::new(
            &vp_address,
            &shell.state,
            &signed_tx.tx,
            &signed_tx.cmt,
            &TxIndex(0),
            &gas_meter,
            &keys_changed,
            &verifiers,
            shell.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        );

        group.bench_function(bench_name, |b| {
            b.iter(|| {
                assert!(
                    PosVp::validate_tx(
                        &ctx,
                        &signed_tx.to_ref(),
                        ctx.keys_changed,
                        ctx.verifiers,
                    )
                    .is_ok()
                )
            })
        });
    }

    group.finish();
}

fn ibc_vp_validate_action(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_ibc_validate_action");

    for bench_name in [
        "open_connection",
        "open_channel",
        "outgoing_transfer",
        "outgoing_shielded_action",
    ] {
        let (shielded_ctx, signed_tx) = prepare_ibc_tx_and_ctx(bench_name);

        let verifiers_from_tx =
            shielded_ctx.shell.write().execute_tx(&signed_tx.to_ref());
        let tx_data = signed_tx.tx.data(&signed_tx.cmt).unwrap();
        let shell_read = shielded_ctx.shell.read();
        let (verifiers, keys_changed) = shell_read
            .state
            .write_log()
            .verifiers_and_changed_keys(&verifiers_from_tx);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ibc = IbcVp::new(Ctx::new(
            &Address::Internal(InternalAddress::Ibc),
            &shell_read.state,
            &signed_tx.tx,
            &signed_tx.cmt,
            &TxIndex(0),
            &gas_meter,
            &keys_changed,
            &verifiers,
            shell_read.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        ));
        // Use an empty verifiers set placeholder for validation, this is only
        // needed in actual txs to addresses whose VPs should be triggered
        let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));

        let exec_ctx = IbcVpContext::new(ibc.ctx.pre());
        let ctx = Rc::new(RefCell::new(exec_ctx));
        let mut actions =
            IbcActions::<_, parameters::Store<_>, token::Store<()>>::new(
                ctx.clone(),
                verifiers.clone(),
            );
        actions.set_validation_params(ibc.validation_params().unwrap());

        let module = create_transfer_middlewares::<_, parameters::Store<_>>(
            ctx.clone(),
            verifiers,
        );
        actions.add_transfer_module(module);
        let module = NftTransferModule::<_, token::Store<()>>::new(ctx);
        actions.add_transfer_module(module);

        group.bench_function(bench_name, |b| {
            b.iter(|| actions.validate::<Transfer>(&tx_data).unwrap())
        });
    }

    group.finish();
}

fn ibc_vp_execute_action(c: &mut Criterion) {
    let mut group = c.benchmark_group("vp_ibc_execute_action");

    for bench_name in [
        "open_connection",
        "open_channel",
        "outgoing_transfer",
        "outgoing_shielded_action",
    ] {
        let (shielded_ctx, signed_tx) = prepare_ibc_tx_and_ctx(bench_name);

        let verifiers_from_tx =
            shielded_ctx.shell.write().execute_tx(&signed_tx.to_ref());
        let shell_read = shielded_ctx.shell.read();
        let tx_data = signed_tx.tx.data(&signed_tx.cmt).unwrap();
        let (verifiers, keys_changed) = shell_read
            .state
            .write_log()
            .verifiers_and_changed_keys(&verifiers_from_tx);

        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ibc = IbcVp::new(Ctx::new(
            &Address::Internal(InternalAddress::Ibc),
            &shell_read.state,
            &signed_tx.tx,
            &signed_tx.cmt,
            &TxIndex(0),
            &gas_meter,
            &keys_changed,
            &verifiers,
            shell_read.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        ));
        // Use an empty verifiers set placeholder for validation, this is only
        // needed in actual txs to addresses whose VPs should be triggered
        let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));

        let exec_ctx = IbcVpContext::new(ibc.ctx.pre());
        let ctx = Rc::new(RefCell::new(exec_ctx));

        let mut actions =
            IbcActions::<_, parameters::Store<_>, token::Store<()>>::new(
                ctx.clone(),
                verifiers.clone(),
            );
        actions.set_validation_params(ibc.validation_params().unwrap());

        let module = create_transfer_middlewares::<_, parameters::Store<_>>(
            ctx.clone(),
            verifiers,
        );
        actions.add_transfer_module(module);
        let module = NftTransferModule::<_, token::Store<()>>::new(ctx);
        actions.add_transfer_module(module);

        group.bench_function(bench_name, |b| {
            b.iter(|| actions.execute::<token::Transfer>(&tx_data).unwrap())
        });
    }

    group.finish();
}

criterion_group!(
    native_vps,
    governance,
    // slash_fund,
    ibc,
    masp,
    masp_check_spend,
    masp_check_convert,
    masp_check_output,
    masp_final_check,
    masp_batch_signature_verification,
    masp_batch_spend_proofs_validate,
    masp_batch_convert_proofs_validate,
    masp_batch_output_proofs_validate,
    vp_multitoken,
    pgf,
    eth_bridge_nut,
    eth_bridge,
    eth_bridge_pool,
    parameters,
    pos,
    ibc_vp_validate_action,
    ibc_vp_execute_action
);
criterion_main!(native_vps);
