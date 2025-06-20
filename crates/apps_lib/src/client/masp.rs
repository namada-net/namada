use std::time::Duration;

use color_eyre::owo_colors::OwoColorize;
#[cfg(feature = "testing")]
use namada_core::masp::AssetData;
use namada_sdk::args::ShieldedSync;
use namada_sdk::control_flow::install_shutdown_signal;
use namada_sdk::error::Error;
#[cfg(any(test, feature = "testing"))]
use namada_sdk::io::DevNullProgressBar;
use namada_sdk::io::{Client, Io, MaybeSend, MaybeSync, display, display_line};
use namada_sdk::masp::{
    IndexerMaspClient, LedgerMaspClient, LinearBackoffSleepMaspClient,
    MaspLocalTaskEnv, ShieldedContext, ShieldedSyncConfig, ShieldedUtils,
};

#[allow(clippy::too_many_arguments)]
pub async fn syncing<
    U: ShieldedUtils + MaybeSend + MaybeSync,
    C: Client + Send + Sync + 'static,
    IO: Io + Send + Sync,
>(
    mut shielded: ShieldedContext<U>,
    client: C,
    args: ShieldedSync,
    io: &IO,
) -> Result<ShieldedContext<U>, Error> {
    let (fetched_bar, scanned_bar, applied_bar) = {
        #[cfg(any(test, feature = "testing"))]
        {
            (DevNullProgressBar, DevNullProgressBar, DevNullProgressBar)
        }

        #[cfg(not(any(test, feature = "testing")))]
        {
            let fetched = kdam::tqdm!(
                total = 0,
                desc = "fetched ",
                animation = "fillup",
                position = 0,
                force_refresh = true,
                dynamic_ncols = true,
                miniters = 0,
                mininterval = 0.05
            );

            let scanned = kdam::tqdm!(
                total = 0,
                desc = "scanned ",
                animation = "fillup",
                position = 1,
                force_refresh = true,
                dynamic_ncols = true,
                miniters = 0,
                mininterval = 0.05
            );

            let applied = kdam::tqdm!(
                total = 0,
                desc = "applied ",
                animation = "fillup",
                position = 2,
                force_refresh = true,
                dynamic_ncols = true,
                miniters = 0,
                mininterval = 0.05
            );

            (fetched, scanned, applied)
        }
    };

    let vks = args
        .viewing_keys
        .into_iter()
        .map(|vk| vk.map(|vk| vk.as_viewing_key()))
        .collect::<Vec<_>>();

    macro_rules! dispatch_client {
        ($client:expr) => {{
            let config = ShieldedSyncConfig::builder()
                .client($client)
                .fetched_tracker(fetched_bar)
                .scanned_tracker(scanned_bar)
                .applied_tracker(applied_bar)
                .shutdown_signal(install_shutdown_signal(false))
                .wait_for_last_query_height(args.wait_for_last_query_height)
                .retry_strategy(args.retry_strategy)
                .block_batch_size(args.block_batch_size)
                .build();

            let env = MaspLocalTaskEnv::new(500)
                .map_err(|e| Error::Other(e.to_string()))?;
            let ctx = shielded
                .sync(
                    env,
                    config,
                    args.last_query_height,
                    &args.spending_keys,
                    &vks,
                )
                .await
                .map(|_| shielded)
                .map_err(|e| Error::Other(e.to_string()));

            display!(io, "\nSyncing finished\n");

            ctx
        }};
    }

    #[cfg(feature = "testing")]
    {
        // Load the confirmed context and update the conversions for the
        // shielded history. This is needed for integration tests only
        // as the cli wallet is not supposed to compile the history of shielded
        // transactions
        shielded.load_confirmed().await;
        for (asset_type, (token, denom, position, epoch, _conv)) in
            namada_sdk::rpc::query_conversions(&client).await?
        {
            let pre_asset_type = AssetData {
                token,
                denom,
                position,
                epoch: Some(epoch),
            };
            shielded.asset_types.insert(asset_type, pre_asset_type);
        }
        shielded
            .save()
            .await
            .map_err(|e| Error::Other(e.to_string()))?;
    }

    let shielded = if let Some(endpoint) = args.with_indexer {
        display_line!(
            io,
            "{}\n",
            "==== Shielded sync started using indexer client ====".bold()
        );

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(60))
            .build()
            .map_err(|err| {
                Error::Other(format!("Failed to build http client: {err}"))
            })?;
        let url = endpoint.as_str().try_into().map_err(|err| {
            Error::Other(format!(
                "Failed to parse API endpoint {endpoint:?}: {err}"
            ))
        })?;

        dispatch_client!(LinearBackoffSleepMaspClient::new(
            IndexerMaspClient::new(
                client,
                url,
                true,
                args.max_concurrent_fetches,
            ),
            Duration::from_millis(5)
        ))?
    } else {
        display_line!(
            io,
            "{}\n",
            "==== Shielded sync started using ledger client ====".bold()
        );

        dispatch_client!(LinearBackoffSleepMaspClient::new(
            LedgerMaspClient::new(client, args.max_concurrent_fetches,),
            Duration::from_millis(5)
        ))?
    };

    Ok(shielded)
}
