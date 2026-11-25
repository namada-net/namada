use namada_sdk::error::Error;
use namada_sdk::io::{Client, Io};
use namada_sdk::rpc::wait_until_node_is_synched;

use crate::tendermint_rpc::client::CompatMode;
use crate::tendermint_rpc::{HttpClient, Url as TendermintUrl};

/// Trait for clients that can be used with the CLI.
#[async_trait::async_trait(?Send)]
pub trait CliClient: Client + Send + Sync + 'static {
    fn from_tendermint_address(address: &TendermintUrl) -> Self;
    async fn wait_until_node_is_synced(
        &self,
        io: &impl Io,
    ) -> Result<(), Error>;
}

#[async_trait::async_trait(?Send)]
impl CliClient for HttpClient {
    fn from_tendermint_address(address: &TendermintUrl) -> Self {
        HttpClient::builder(address.clone().try_into().unwrap())
            .compat_mode(CompatMode::V0_37)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap()
    }

    async fn wait_until_node_is_synced(
        &self,
        io: &impl Io,
    ) -> Result<(), Error> {
        wait_until_node_is_synched(self, io).await
    }
}

#[derive(Copy, Clone)]
pub struct CliIo;

#[async_trait::async_trait(?Send)]
impl Io for CliIo {}

pub struct CliApi;
