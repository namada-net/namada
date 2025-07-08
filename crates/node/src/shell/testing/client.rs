use clap::Command as App;
use eyre::{Report, WrapErr};
use namada_apps_lib::cli::api::{CliApi, CliClient};
use namada_apps_lib::cli::args::Global;
use namada_apps_lib::cli::{
    Cmd, Context, NamadaClient, NamadaRelayer, args, cmds,
};
use namada_sdk::args::{SdkTypes, TxExpiration};
use namada_sdk::error::Error as SdkError;
use namada_sdk::io::Io;
use namada_sdk::signing::{SigningTxData, default_sign};
use namada_sdk::tx::data::GasLimit;
use namada_sdk::tx::{ProcessTxResponse, Tx};
use namada_sdk::{signing, tendermint_rpc, tx};

use super::node::MockNode;
use crate::shell::testing::utils::{Bin, TestingIo};

pub fn run(
    node: &MockNode,
    who: Bin,
    mut args: Vec<&str>,
) -> Result<(), Report> {
    let global = {
        let locked = node.shell.lock().unwrap();
        Global {
            is_pre_genesis: false,
            chain_id: Some(locked.chain_id.clone()),
            base_dir: locked.base_dir.clone(),
            wasm_dir: Some(locked.wasm_dir.clone()),
        }
    };
    let ctx = Context::new::<TestingIo>(global.clone())?;

    let rt = tokio::runtime::Runtime::new().unwrap();
    match who {
        Bin::Node => {
            unreachable!("Node commands aren't supported by integration tests")
        }
        Bin::Client => {
            args.insert(0, "client");
            let app = App::new("test");
            let app = cmds::NamadaClient::add_sub(args::Global::def(app));
            let matches = app.get_matches_from(args.clone());
            let cmd = match cmds::NamadaClient::parse(&matches)
                .expect("Could not parse client command")
            {
                cmds::NamadaClient::WithContext(sub_cmd) => {
                    NamadaClient::WithContext(Box::new((sub_cmd, ctx)))
                }
                cmds::NamadaClient::WithoutContext(sub_cmd) => {
                    NamadaClient::WithoutContext(Box::new((sub_cmd, global)))
                }
            };
            let result = rt.block_on(CliApi::handle_client_command(
                Some(node.clone()),
                cmd,
                TestingIo,
            ));
            if let Err(err) = &result {
                TestingIo.eprintln(format!("{}", err));
            }
            result
        }
        Bin::Wallet => {
            args.insert(0, "wallet");
            let app = App::new("test");
            let app = cmds::NamadaWallet::add_sub(args::Global::def(app));
            let matches = app.get_matches_from(args.clone());

            let cmd = cmds::NamadaWallet::parse(&matches)
                .expect("Could not parse wallet command");
            rt.block_on(CliApi::handle_wallet_command(cmd, ctx, &TestingIo))
        }
        Bin::Relayer => {
            args.insert(0, "relayer");
            let app = App::new("test");
            let app = cmds::NamadaRelayer::add_sub(args::Global::def(app));
            let matches = app.get_matches_from(args.clone());
            let cmd = match cmds::NamadaRelayer::parse(&matches)
                .expect("Could not parse relayer command")
            {
                cmds::NamadaRelayer::EthBridgePool(
                    cmds::EthBridgePool::WithContext(sub_cmd),
                ) => NamadaRelayer::EthBridgePoolWithCtx(Box::new((
                    sub_cmd, ctx,
                ))),
                cmds::NamadaRelayer::EthBridgePool(
                    cmds::EthBridgePool::WithoutContext(sub_cmd),
                ) => NamadaRelayer::EthBridgePoolWithoutCtx(sub_cmd),
                cmds::NamadaRelayer::ValidatorSet(sub_cmd) => {
                    NamadaRelayer::ValidatorSet(sub_cmd)
                }
            };
            rt.block_on(CliApi::handle_relayer_command(
                Some(node.clone()),
                cmd,
                TestingIo,
            ))
        }
    }
}

#[async_trait::async_trait(?Send)]
impl CliClient for MockNode {
    fn from_tendermint_address(_: &crate::tendermint_rpc::Url) -> Self {
        unreachable!("MockNode should always be instantiated at test start.")
    }

    async fn wait_until_node_is_synced(
        &self,
        _io: &impl Io,
    ) -> Result<(), SdkError> {
        Ok(())
    }
}

/// Manually sign a tx. This can be used to sign a tx that was dumped
pub fn sign_tx(
    node: &MockNode,
    tx: Tx,
    signing: SigningTxData,
    // this is only used to give the password for decrypting keys to the wallet
    args: &args::Tx,
) -> Result<Tx, Report> {
    use namada_sdk::Namada;
    let global = {
        let locked = node.shell.lock().unwrap();
        Global {
            is_pre_genesis: false,
            chain_id: Some(locked.chain_id.clone()),
            base_dir: locked.base_dir.clone(),
            wasm_dir: Some(locked.wasm_dir.clone()),
        }
    };
    let ctx = Context::new::<TestingIo>(global.clone())
        .wrap_err("Failed to build context")?
        .to_sdk(node.clone(), TestingIo);
    let rt = tokio::runtime::Runtime::new().unwrap();

    let (mut batched_tx, batched_signing_data) =
        tx::build_batch(vec![(tx, signing)])
            .wrap_err("Failed to build tx batch")?;
    rt.block_on(async {
        for sig_data in batched_signing_data {
            signing::sign_tx(
                ctx.wallet_lock(),
                args,
                &mut batched_tx,
                sig_data,
                default_sign,
                (),
            )
            .await
            .wrap_err("Signing tx failed")?;
        }
        Ok::<(), Report>(())
    })?;
    Ok(batched_tx)
}

/// Manually submit a tx. Used for txs that have been manually constructed
/// instead of by the CLI
pub fn submit_custom(
    node: &MockNode,
    tx: Tx,
    // this is only used to give the password for decrypting keys to the wallet
    args: &args::Tx,
) -> Result<ProcessTxResponse, Report> {
    use namada_sdk::Namada;
    let global = {
        let locked = node.shell.lock().unwrap();
        Global {
            is_pre_genesis: false,
            chain_id: Some(locked.chain_id.clone()),
            base_dir: locked.base_dir.clone(),
            wasm_dir: Some(locked.wasm_dir.clone()),
        }
    };
    let ctx = Context::new::<TestingIo>(global.clone())
        .wrap_err("Failed to build context")?
        .to_sdk(node.clone(), TestingIo);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async { ctx.submit(tx, args).await })
        .wrap_err("Failed to submit tx")
}

pub fn dummy_args(node: &MockNode) -> args::Tx<SdkTypes> {
    use std::str::FromStr;
    args::Tx {
        dry_run: false,
        dry_run_wrapper: false,
        dump_tx: false,
        dump_wrapper_tx: false,
        output_folder: None,
        force: false,
        broadcast_only: false,
        ledger_address: tendermint_rpc::Url::from_str("http://127.0.0.1:26567")
            .unwrap(),
        initialized_account_alias: None,
        wallet_alias_force: false,
        fee_amount: None,
        wrapper_fee_payer: None,
        fee_token: node.native_token(),
        gas_limit: GasLimit::from(1000000),
        expiration: TxExpiration::NoExpiration,
        chain_id: Some(node.chain_id()),
        signing_keys: vec![],
        tx_reveal_code_path: Default::default(),
        password: None,
        memo: None,
        use_device: false,
        device_transport: Default::default(),
    }
}
