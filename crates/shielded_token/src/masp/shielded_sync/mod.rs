use std::collections::BTreeMap;
#[cfg(not(target_family = "wasm"))]
use std::future::Future;
use std::ops::ControlFlow;

#[cfg(not(target_family = "wasm"))]
#[cfg(feature = "std")]
use eyre::eyre;
use masp_primitives::sapling::ViewingKey;
use masp_primitives::sapling::note_encryption::{
    PreparedIncomingViewingKey, try_sapling_note_decryption,
};
use masp_primitives::transaction::components::OutputDescription;
use masp_primitives::transaction::{Authorization, Authorized, Transaction};
#[cfg(not(target_family = "wasm"))]
use namada_core::task_env::{
    LocalSetSpawner, LocalSetTaskEnvironment, TaskEnvironment,
};
use namada_io::{MaybeSend, MaybeSync};
use typed_builder::TypedBuilder;

use super::shielded_sync::utils::{MaspClient, RetryStrategy};
use crate::masp::shielded_sync::dispatcher::Dispatcher;
use crate::masp::utils::DecryptedData;
use crate::masp::{NETWORK, ShieldedUtils};

pub mod dispatcher;
pub mod utils;

const DEFAULT_BUF_SIZE: usize = 32;
const DEFAULT_BATCH_SIZE: usize = 10;

/// A configuration used to tune the concurrency parameters of
/// the shielded sync and the client used to fetch data.
#[derive(Clone, TypedBuilder)]
pub struct ShieldedSyncConfig<M, T, I> {
    client: M,
    fetched_tracker: T,
    scanned_tracker: T,
    applied_tracker: T,
    shutdown_signal: I,
    #[builder(default = false)]
    wait_for_last_query_height: bool,
    #[builder(default = RetryStrategy::Forever)]
    retry_strategy: RetryStrategy,
    #[builder(default = DEFAULT_BUF_SIZE)]
    channel_buffer_size: usize,
    #[builder(default = DEFAULT_BATCH_SIZE)]
    block_batch_size: usize,
}

/// A task env whose backing thread-pool uses a no-op
/// panic handler. Custom for MASP dispatchers.
#[cfg(not(target_family = "wasm"))]
pub struct MaspLocalTaskEnv(LocalSetTaskEnvironment);

#[cfg(not(target_family = "wasm"))]
#[cfg(feature = "std")]
impl MaspLocalTaskEnv {
    /// create a new [`MaspLocalTaskEnv`]
    pub fn new(num_threads: usize) -> Result<Self, eyre::Error> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .panic_handler(|_| {})
            .build()
            .map_err(|err| eyre!("Failed to create thread pool: {err}"))?;
        Ok(Self(LocalSetTaskEnvironment::new(pool)))
    }
}

#[cfg(not(target_family = "wasm"))]
impl TaskEnvironment for MaspLocalTaskEnv {
    type Spawner = LocalSetSpawner;

    async fn run<M, F, R>(self, main: M) -> R
    where
        M: FnOnce(Self::Spawner) -> F,
        F: Future<Output = R>,
    {
        self.0.run(main).await
    }
}

impl<M, T, I> ShieldedSyncConfig<M, T, I>
where
    M: MaspClient,
{
    /// Retrieve the [`Dispatcher`] used to run shielded sync.
    pub async fn dispatcher<U, S>(
        self,
        spawner: S,
        utils: &U,
    ) -> Dispatcher<S, M, U, T, I>
    where
        U: ShieldedUtils + MaybeSend + MaybeSync,
    {
        dispatcher::new(
            spawner,
            self.client,
            utils,
            dispatcher::Config {
                fetched_tracker: self.fetched_tracker,
                scanned_tracker: self.scanned_tracker,
                applied_tracker: self.applied_tracker,
                shutdown_signal: self.shutdown_signal,
                retry_strategy: self.retry_strategy,
                block_batch_size: self.block_batch_size,
                channel_buffer_size: self.channel_buffer_size,
                wait_for_last_query_height: self.wait_for_last_query_height,
            },
        )
        .await
    }
}

/// Try to decrypt a MASP transaction with the provided key
pub fn trial_decrypt(
    shielded: Transaction,
    vk: ViewingKey,
    mut interrupted: impl FnMut() -> bool,
) -> ControlFlow<(), BTreeMap<usize, DecryptedData>> {
    type Proof = OutputDescription<
        <
        <Authorized as Authorization>::SaplingAuth
        as masp_primitives::transaction::components::sapling::Authorization
        >::Proof
    >;

    shielded
        .sapling_bundle()
        .map_or(&vec![], |x| &x.shielded_outputs)
        .iter()
        .enumerate()
        .try_fold(BTreeMap::new(), |mut accum, (note_pos_offset, so)| {
            if interrupted() {
                return ControlFlow::Break(());
            }
            // Let's try to see if this viewing key can decrypt latest
            // note
            if let Some(decrypted) = try_sapling_note_decryption::<_, Proof>(
                &NETWORK,
                1.into(),
                &PreparedIncomingViewingKey::new(&vk.ivk()),
                so,
            ) {
                accum.insert(note_pos_offset, decrypted);
            }
            ControlFlow::Continue(accum)
        })
}
