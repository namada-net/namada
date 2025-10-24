use clap::Command as App;
use eyre::Report;
use namada_apps_lib::cli::api::{CliApi, CliClient};
use namada_apps_lib::cli::args::Global;
use namada_apps_lib::cli::{Cmd, Context, NamadaClient, args, cmds};
use namada_sdk::error::Error as SdkError;
use namada_sdk::io::Io;

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
