use std::net::SocketAddr;
use std::ops::ControlFlow;

use namada_sdk::control_flow::time;
use namada_sdk::time::{DateTimeUtc, Utc};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::tendermint_rpc::client::CompatMode;
use crate::tendermint_rpc::{Client, HttpClient};

const DEFAULT_BROADCAST_TIMEOUT: u64 = 180;
const BROADCASTER_TIMEOUT_ENV_VAR: &str = "NAMADA_BROADCASTER_TIMEOUT_SECS";

/// A service for broadcasting txs via an HTTP client.
/// The receiver is for receiving message payloads for other services
/// to be broadcast.
pub struct Broadcaster {
    client: HttpClient,
    receiver: UnboundedReceiver<Vec<u8>>,
}

impl Broadcaster {
    /// Create a new broadcaster that will send Http messages
    /// over the given url.
    pub fn new(url: SocketAddr, receiver: UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            client: HttpClient::builder(
                format!("http://{}", url).as_str().try_into().unwrap(),
            )
            .compat_mode(CompatMode::V0_38)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap(),
            receiver,
        }
    }

    /// Loop forever, broadcasting messages that have been received
    /// by the receiver
    async fn run_loop(&mut self, genesis_time: DateTimeUtc) {
        // wait for start time if necessary
        #[allow(clippy::disallowed_methods)]
        let now = Utc::now();
        if let Ok(sleep_time) =
            genesis_time.0.signed_duration_since(now).to_std()
        {
            if !sleep_time.is_zero() {
                tokio::time::sleep(sleep_time).await;
            }
        }
        let result = time::Sleep {
            strategy: time::ExponentialBackoff {
                base: 2,
                as_duration: time::Duration::from_secs,
            },
        }
        .run(|| async {
            let timeout =
                if let Ok(value) = std::env::var(BROADCASTER_TIMEOUT_ENV_VAR) {
                    value.parse::<u64>().unwrap_or(DEFAULT_BROADCAST_TIMEOUT)
                } else {
                    DEFAULT_BROADCAST_TIMEOUT
                };
            let now = {
                #[allow(clippy::disallowed_methods)]
                time::Instant::now()
            };
            let status_result = time::Sleep {
                strategy: time::Constant(time::Duration::from_secs(1)),
            }
            .timeout(
                #[allow(clippy::arithmetic_side_effects)]
                {
                    now + time::Duration::from_secs(timeout)
                },
                || async {
                    match self.client.status().await {
                        Ok(status) => ControlFlow::Break(status),
                        Err(_) => ControlFlow::Continue(()),
                    }
                },
            )
            .await;
            let status = match status_result {
                Ok(status) => status,
                Err(_) => return ControlFlow::Break(Err(())),
            };
            if status.sync_info.catching_up {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(Ok(()))
            }
        })
        .await;
        if let Err(()) = result {
            tracing::error!("Broadcaster failed to connect to CometBFT node");
            return;
        } else {
            tracing::info!("Broadcaster successfully started.");
        }
        loop {
            if let Some(msg) = self.receiver.recv().await {
                let _ = self.client.broadcast_tx_sync(msg).await;
            }
        }
    }

    /// Loop until an abort signal is received, forwarding messages over
    /// the HTTP client as they are received from the receiver.
    pub async fn run(
        &mut self,
        abort_recv: tokio::sync::oneshot::Receiver<()>,
        genesis_time: DateTimeUtc,
    ) {
        tracing::info!("Starting broadcaster.");
        tokio::select! {
            _ = self.run_loop(genesis_time) => {
                tracing::error!("Broadcaster unexpectedly shut down.");
                tracing::info!("Shutting down broadcaster...");
            },
            resp_sender = abort_recv => {
                match resp_sender {
                    Ok(_) => {
                        tracing::info!("Shutting down broadcaster...");
                    },
                    Err(err) => {
                        tracing::error!("The broadcaster abort sender has unexpectedly dropped: {}", err);
                        tracing::info!("Shutting down broadcaster...");
                    }
                }
            }
        }
    }
}
