//! Node utils commands handlers

use std::cell::RefCell;
use std::str::FromStr;

use namada_apps_lib::cli::api::CliIo;
use namada_apps_lib::cli::args::{self, DryRunProposal, TestGenesis};
use namada_apps_lib::client::utils::PRE_GENESIS_DIR;
use namada_apps_lib::config::genesis::{self, AddrOrPk};
use namada_apps_lib::{cli, wallet};
use namada_sdk::address::{Address, ImplicitAddress};
use namada_sdk::gas::TxGasMeter;
use namada_sdk::key::common;
use namada_sdk::state::{
    FullAccessState, Sha256Hasher, StorageWrite, TempWlState, TxIndex,
};
use namada_sdk::tx::data::TxType;
use namada_sdk::tx::{self, Tx};
use namada_sdk::wallet::FindKeyError;
use namada_sdk::{encode, governance, parameters};
use namada_vm::WasmCacheRwAccess;
use namada_vm::wasm::{TxCache, VpCache};
use tracing::info;

use crate::tendermint::Timeout;
use crate::{protocol, storage};

pub fn test_genesis(args: TestGenesis, global_args: args::Global) {
    let TestGenesis {
        path,
        wasm_dir,
        check_can_sign,
    } = args;

    let Some(templates) = genesis::templates::load_and_validate(&path) else {
        eprintln!("Unable to load the genesis templates");
        cli::safe_exit(1);
    };
    let genesis = genesis::chain::finalize(
        templates,
        FromStr::from_str("namada-dryrun").unwrap(),
        Default::default(),
        Timeout::from_str("30s").unwrap(),
    );
    let chain_id = &genesis.metadata.chain_id;
    let test_dir = tempfile::tempdir().unwrap();
    let config = crate::config::Config::load(test_dir.path(), chain_id, None);
    genesis
        .write_toml_files(&test_dir.path().join(chain_id.to_string()))
        .unwrap();
    crate::test_genesis_files(config.ledger, genesis.clone(), wasm_dir);

    if !check_can_sign.is_empty() {
        let wallet_path = global_args.base_dir.join(PRE_GENESIS_DIR);
        let mut wallet = if wallet::exists(&wallet_path) {
            wallet::load(&wallet_path).unwrap()
        } else {
            panic!(
                "Could not find wallet at {}.",
                wallet_path.to_string_lossy()
            );
        };

        let mut all_valid = true;

        type WalletRes = Result<common::SecretKey, FindKeyError>;
        let handle_wallet_result =
            |searched: String, result: WalletRes| match result {
                Ok(_) => {
                    println!("Able to sign with {searched}");
                    true
                }
                Err(err) => {
                    eprintln!("Unable to sign with {searched}. {err}");
                    false
                }
            };

        for addr_or_pk in check_can_sign {
            match &addr_or_pk {
                AddrOrPk::PublicKey(pk) => {
                    if !handle_wallet_result(
                        pk.to_string(),
                        wallet.find_key_by_pk(&pk.raw, None),
                    ) {
                        all_valid = false;
                    }
                }
                AddrOrPk::Address(addr) => {
                    match &addr {
                        Address::Established(_) => {
                            // Find PK(s) of the address in genesis
                            if let Some(txs) = genesis
                                .transactions
                                .established_account
                                .as_ref()
                            {
                                if let Some(tx) =
                                    txs.iter().find(|tx| &tx.address == addr)
                                {
                                    println!(
                                        "Found a matching genesis established \
                                         account tx with {} public key(s).",
                                        tx.tx.public_keys.len()
                                    );
                                    for pk in &tx.tx.public_keys {
                                        if !handle_wallet_result(
                                            format!("{pk} for {addr}"),
                                            wallet
                                                .find_key_by_pk(&pk.raw, None),
                                        ) {
                                            all_valid = false;
                                        }
                                    }
                                } else {
                                    eprintln!(
                                        "No genesis established account txs \
                                         with a matching address {addr} found"
                                    );
                                    all_valid = false;
                                }
                            } else {
                                eprintln!(
                                    "No genesis established account txs \
                                     found. Cannot check address {addr}."
                                );
                                all_valid = false;
                            }
                        }
                        Address::Implicit(ImplicitAddress(pkh)) => {
                            if !handle_wallet_result(
                                addr.to_string(),
                                wallet.find_key_by_pkh(pkh, None),
                            ) {
                                all_valid = false;
                            }
                        }
                        Address::Internal(_) => {
                            eprintln!("Unexpected internal address {addr}");
                            all_valid = false;
                        }
                    }
                }
            }
        }
        if !all_valid {
            cli::safe_exit(1);
        }
    }
}

pub fn dry_run_proposal(
    args: DryRunProposal,
    global_args: args::Global,
) -> eyre::Result<()> {
    let DryRunProposal { wasm_path } = args;
    let test_dir = tempfile::tempdir().unwrap();

    let proposal_code = std::fs::read(&wasm_path).unwrap_or_else(|err| {
        eprintln!(
            "Couldn't read WASM at path at {}. Error: {err}",
            wasm_path.to_string_lossy()
        );
        cli::safe_exit(1)
    });

    let ctx = cli::Context::new::<CliIo>(global_args)?;
    let chain_ctx = ctx.take_chain_or_exit();
    let native_token = chain_ctx.native_token.clone();
    let config = &chain_ctx.config.ledger;
    let chain_id = &config.chain_id;
    let db_path = config.shell.db_dir(chain_id);
    let mut state: TempWlState<storage::PersistentDB, Sha256Hasher> =
        FullAccessState::open(
            db_path,
            None,
            chain_id.clone(),
            native_token,
            config.shell.storage_read_past_height_limit,
            |_key| true,
        )
        .with_temp_write_log();

    // A fake proposal ID
    let id = u64::MAX;
    // Instruct VPs that this is a gov proposal
    let pending_execution_key =
        governance::storage::keys::get_proposal_execution_key(id);
    state.write(&pending_execution_key, ())?;

    let gas_scale = parameters::get_gas_scale(&state)
        .expect("Failed to get gas scale from parameters");
    let height = state.in_mem().get_last_block_height();

    let mut tx = Tx::from_type(TxType::Raw);
    tx.header.chain_id = chain_id.clone();
    tx.set_data(tx::Data::new(encode(&id)));
    tx.set_code(tx::Code::new(proposal_code, None));

    let mut vp_wasm_cache =
        VpCache::<WasmCacheRwAccess>::new(test_dir.path(), usize::MAX);
    let mut tx_wasm_cache =
        TxCache::<WasmCacheRwAccess>::new(test_dir.path(), usize::MAX);

    info!("Executing the proposal code...");
    let dispatch_result = protocol::dispatch_tx(
        &tx,
        protocol::DispatchArgs::Raw {
            wrapper_hash: None,
            tx_index: TxIndex::default(),
            wrapper_tx_result: None,
            vp_wasm_cache: &mut vp_wasm_cache,
            tx_wasm_cache: &mut tx_wasm_cache,
            height,
        },
        // No gas limit for governance proposal
        &RefCell::new(TxGasMeter::new(u64::MAX, gas_scale)),
        &mut state,
    );
    info!("Execution finished");
    // Governance must construct the tx with data and code commitments
    let cmt = tx.first_commitments().unwrap().to_owned();
    match dispatch_result {
        Ok(tx_result) => match tx_result
            .get_inner_tx_result(None, either::Right(&cmt))
            .expect("Proposal tx must have a result")
        {
            Ok(batched_result) => {
                if batched_result.is_accepted() {
                    println!(
                        "Governance proposal was accepted with result: {}",
                        batched_result.vps_result
                    );
                } else {
                    println!(
                        "Governance proposal rejected by VP(s): {}",
                        batched_result.vps_result
                    );
                }
            }
            Err(e) => {
                println!("Error executing governance proposal {e}",);
            }
        },
        Err(e) => {
            println!("Error executing governance proposal {}", e.error);
        }
    };

    Ok(())
}
