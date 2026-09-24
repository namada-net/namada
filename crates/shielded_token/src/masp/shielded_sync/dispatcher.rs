use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool, AtomicUsize};
use std::task::{Context, Poll};

use borsh::{BorshDeserialize, BorshSerialize};
use eyre::{ContextCompat, WrapErr, eyre};
use futures::future::{Either, select};
use futures::task::AtomicWaker;
use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::{Node, ViewingKey};
use masp_primitives::transaction::Transaction;
use namada_core::chain::BlockHeight;
use namada_core::collections::{HashMap, HashSet};
use namada_core::control_flow::ShutdownSignal;
use namada_core::control_flow::time::{Duration, LinearBackoff, Sleep};
use namada_core::hints;
use namada_core::task_env::TaskSpawner;
use namada_io::{MaybeSend, MaybeSync, ProgressBar};
use namada_wallet::{DatedKeypair, DatedSpendingKey};

use super::utils::{
    IndexedNoteEntry, MaspClient, MaspClientCapabilities, MaspIndexedTx,
};
use crate::masp::bridge_tree::BridgeTree;
use crate::masp::shielded_sync::trial_decrypt;
use crate::masp::utils::{
    DecryptedData, Fetched, RetryStrategy, TrialDecrypted, blocks_left_to_fetch,
};
use crate::masp::{
    MaspExtendedSpendingKey, NoteIndex, NotePosition, ShieldedUtils,
    ShieldedWallet, WitnessMap, to_viewing_key,
};

struct AsyncCounterInner {
    waker: AtomicWaker,
    count: AtomicUsize,
}

impl AsyncCounterInner {
    fn increment(&self) {
        self.count.fetch_add(1, atomic::Ordering::Relaxed);
    }

    fn decrement_then_wake(&self) -> bool {
        // NB: if the prev value is 1, the new value
        // is eq to 0, which means we must wake the
        // waiting future
        self.count.fetch_sub(1, atomic::Ordering::Relaxed) == 1
    }

    fn value(&self) -> usize {
        self.count.load(atomic::Ordering::Relaxed)
    }
}

struct AsyncCounter {
    inner: Arc<AsyncCounterInner>,
}

impl AsyncCounter {
    fn new() -> Self {
        Self {
            inner: Arc::new(AsyncCounterInner {
                waker: AtomicWaker::new(),
                count: AtomicUsize::new(0),
            }),
        }
    }
}

impl Clone for AsyncCounter {
    fn clone(&self) -> Self {
        let inner = Arc::clone(&self.inner);
        inner.increment();
        Self { inner }
    }
}

impl Drop for AsyncCounter {
    fn drop(&mut self) {
        if self.inner.decrement_then_wake() {
            self.inner.waker.wake();
        }
    }
}

impl Future for AsyncCounter {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.inner.value() == 0 {
            Poll::Ready(())
        } else {
            self.inner.waker.register(cx.waker());
            Poll::Pending
        }
    }
}

#[derive(Clone, Default)]
pub struct AtomicFlag {
    inner: Arc<AtomicBool>,
}

impl AtomicFlag {
    pub fn set(&self) {
        self.inner.store(true, atomic::Ordering::Relaxed)
    }

    pub fn get(&self) -> bool {
        self.inner.load(atomic::Ordering::Relaxed)
    }
}

#[derive(Clone, Default)]
struct PanicFlag {
    #[cfg(not(target_family = "wasm"))]
    inner: AtomicFlag,
}

impl PanicFlag {
    #[inline(always)]
    fn panicked(&self) -> bool {
        #[cfg(target_family = "wasm")]
        {
            false
        }

        #[cfg(not(target_family = "wasm"))]
        {
            self.inner.get()
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl Drop for PanicFlag {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.inner.set();
        }
    }
}

struct TaskError<C> {
    error: eyre::Error,
    context: C,
}

#[allow(clippy::large_enum_variant, clippy::type_complexity)]
enum Message {
    FirstCommitmentTree(
        Result<(BlockHeight, CommitmentTree<Node>), TaskError<BlockHeight>>,
    ),
    UpdateCommitmentTree(
        Result<(BlockHeight, CommitmentTree<Node>), TaskError<BlockHeight>>,
    ),
    UpdateNoteIndex(
        Result<
            (BlockHeight, BTreeMap<MaspIndexedTx, NotePosition>),
            TaskError<BlockHeight>,
        >,
    ),
    UpdateWitnessMap(
        Result<
            (BlockHeight, HashMap<NotePosition, IncrementalWitness<Node>>),
            TaskError<BlockHeight>,
        >,
    ),
    FetchTxs(
        Result<
            (BlockHeight, BlockHeight, Vec<IndexedNoteEntry>),
            TaskError<[BlockHeight; 2]>,
        >,
    ),
    TrialDecrypt(
        MaspIndexedTx,
        ViewingKey,
        ControlFlow<(), BTreeMap<usize, DecryptedData>>,
    ),
}

struct DispatcherTasks<Spawner> {
    spawner: Spawner,
    message_receiver: flume::Receiver<Message>,
    message_sender: flume::Sender<Message>,
    active_tasks: AsyncCounter,
    panic_flag: PanicFlag,
}

impl<Spawner> DispatcherTasks<Spawner> {
    async fn get_next_message(&mut self) -> Option<Message> {
        if let Either::Left((maybe_message, _)) =
            select(self.message_receiver.recv_async(), &mut self.active_tasks)
                .await
        {
            let Ok(message) = maybe_message else {
                unreachable!("There must be at least one sender alive");
            };
            Some(message)
        } else {
            // NB: queueing a message to a channel doesn't mean we
            // actually consume it. we must wait for the channel to
            // be drained when all tasks have returned. the spin loop
            // hint below helps the compiler to optimize the `try_recv`
            // branch, to avoid maxing out the cpu.
            std::hint::spin_loop();
            self.message_receiver.try_recv().ok()
        }
    }

    #[inline(always)]
    fn try_recv_orphaned_message(&self) -> Option<Message> {
        self.message_receiver.try_recv().ok()
    }
}

/// Shielded sync cache.
#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct DispatcherCache {
    pub(crate) first_commitment_tree:
        Option<(BlockHeight, CommitmentTree<Node>)>,
    pub(crate) commitment_tree: Option<(BlockHeight, CommitmentTree<Node>)>,
    pub(crate) witness_map: Option<(BlockHeight, WitnessMap)>,
    pub(crate) note_index: Option<(BlockHeight, NoteIndex)>,
    pub(crate) fetched: Fetched,
    pub(crate) trial_decrypted: TrialDecrypted,
}

#[derive(Debug)]
enum DispatcherState {
    Normal,
    Interrupted,
    Errored(eyre::Error),
}

#[derive(Default, Debug)]
struct InitialState {
    synced: bool,
    start_height: BlockHeight,
    last_query_height: BlockHeight,
}

pub struct Config<T, I> {
    pub wait_for_last_query_height: bool,
    pub retry_strategy: RetryStrategy,
    pub block_batch_size: usize,
    pub channel_buffer_size: usize,
    pub fetched_tracker: T,
    pub scanned_tracker: T,
    pub applied_tracker: T,
    pub shutdown_signal: I,
}

/// State of different fetch jobs.
#[derive(Default)]
enum FetchState {
    #[default]
    NothingToFetch,
    Fetching {
        left: usize,
    },
    Complete,
}

/// Shielded sync message dispatcher.
pub struct Dispatcher<S, M, U, T, I>
where
    U: ShieldedUtils,
{
    client: M,
    birthdays: HashMap<ViewingKey, BlockHeight>,
    state: DispatcherState,
    tasks: DispatcherTasks<S>,
    ctx: ShieldedWallet<U>,
    config: Config<T, I>,
    cache: DispatcherCache,
    interrupt_flag: AtomicFlag,
    orphaned_flag: AtomicFlag,
    fetch_state: FetchState,
}

/// Create a new dispatcher in the initial state.
///
/// This function assumes that the provided shielded context has
/// already been loaded from storage.
pub async fn new<S, M, U, T, I>(
    spawner: S,
    client: M,
    utils: &U,
    config: Config<T, I>,
) -> Dispatcher<S, M, U, T, I>
where
    U: ShieldedUtils + MaybeSend + MaybeSync,
{
    let ctx = {
        let mut ctx = ShieldedWallet {
            utils: utils.clone(),
            ..Default::default()
        };

        ctx.load().await;

        ctx
    };

    let state = DispatcherState::Normal;

    let (message_sender, message_receiver) =
        flume::bounded(config.channel_buffer_size);

    let tasks = DispatcherTasks {
        spawner,
        message_receiver,
        message_sender,
        active_tasks: AsyncCounter::new(),
        panic_flag: PanicFlag::default(),
    };

    #[allow(clippy::disallowed_methods)]
    let cache = ctx.utils.cache_load().await.unwrap_or_default();

    Dispatcher {
        birthdays: HashMap::new(),
        state,
        ctx,
        tasks,
        client,
        config,
        cache,
        interrupt_flag: Default::default(),
        orphaned_flag: Default::default(),
        fetch_state: Default::default(),
    }
}

impl<S, M, U, T, I> Dispatcher<S, M, U, T, I>
where
    S: TaskSpawner,
    M: MaspClient + Send + Sync + Unpin + 'static,
    U: ShieldedUtils + MaybeSend + MaybeSync,
    T: ProgressBar,
    I: ShutdownSignal,
{
    /// Run the dispatcher
    pub async fn run(
        mut self,
        last_query_height: Option<BlockHeight>,
        sks: &[DatedSpendingKey],
        fvks: &[DatedKeypair<ViewingKey>],
    ) -> Result<Option<ShieldedWallet<U>>, eyre::Error> {
        let initial_state = self
            .perform_initial_setup(last_query_height, sks, fvks)
            .await?;

        if initial_state.synced {
            self.finish_progress_bars();
            return Ok(Some(self.ctx));
        }

        self.check_exit_conditions();

        while let Some(message) = self.tasks.get_next_message().await {
            self.check_exit_conditions();
            self.handle_incoming_message(message);
        }

        match std::mem::replace(&mut self.state, DispatcherState::Normal) {
            DispatcherState::Errored(err) => {
                self.finish_progress_bars();
                self.save_cache().await;
                Err(err)
            }
            DispatcherState::Interrupted => {
                self.finish_progress_bars();
                self.save_cache().await;
                Ok(None)
            }
            DispatcherState::Normal => {
                self.apply_cache_to_shielded_context(&initial_state)?;
                self.finish_progress_bars();
                self.ctx.save().await.map_err(|err| {
                    eyre!("Failed to save the shielded context: {err}")
                })?;
                self.save_cache().await;
                Ok(Some(self.ctx))
            }
        }
    }

    fn force_redraw_progress_bars(&mut self) {
        self.config.fetched_tracker.increment_by(0);
        self.config.scanned_tracker.increment_by(0);
        self.config.applied_tracker.increment_by(0);
    }

    fn finish_progress_bars(&mut self) {
        self.config.fetched_tracker.finish();
        self.config.scanned_tracker.finish();
        self.config.applied_tracker.finish();
    }

    async fn save_cache(&mut self) {
        if let Err(e) = self.ctx.utils.cache_save(&self.cache).await {
            self.config.fetched_tracker.message(format!(
                "Failed to save shielded sync cache with error {e}"
            ));
        }
    }

    fn apply_cache_to_shielded_context(
        &mut self,
        InitialState {
            last_query_height, ..
        }: &InitialState,
    ) -> Result<(), eyre::Error> {
        // NB: Load the first commitment tree from cache
        if let Some((_, ct)) = self.cache.first_commitment_tree.take() {
            self.ctx.tree = BridgeTree::from_commitment_tree(ct)?;
        }

        for (masp_indexed_tx, stx_batch) in self.cache.fetched.take() {
            self.try_get_optional_masp_data();

            if masp_indexed_tx.indexed_tx.block_height > self.ctx.synced_height
            {
                let cmt_tree_still_fetching = !self.has_optional_masp_data();

                if cmt_tree_still_fetching {
                    self.ctx.update_witnesses(
                        masp_indexed_tx,
                        &stx_batch,
                        &self.cache.trial_decrypted,
                    )?;
                }

                self.ctx.save_shielded_spends(
                    &stx_batch,
                    cmt_tree_still_fetching,
                    #[cfg(feature = "historic")]
                    Some(masp_indexed_tx.indexed_tx),
                )?;
            }

            let first_note_pos = self
                .ctx
                .note_index
                .get(&masp_indexed_tx)
                .copied()
                .with_context(|| {
                    format!(
                        "Could not locate the first note position of the MASP \
                         tx at {masp_indexed_tx:?}"
                    )
                })?;

            for vk_index in 0..self.ctx.pos_map.len() {
                let vk = self.ctx.pos_map.get_index(vk_index).unwrap().0;

                if !self.vk_is_outdated(vk, &masp_indexed_tx) {
                    // NB: skip keys that are synced past the given
                    // `masp_indexed_tx`
                    continue;
                }

                // NB: copy the viewing key onto the stack, to remove
                // the borrow and allow mutating through `self.ctx`
                let vk = *vk;

                for (note_pos_offset, (note, pa, memo)) in self
                    .cache
                    .trial_decrypted
                    .take(&masp_indexed_tx, &vk)
                    .unwrap_or_default()
                {
                    self.ctx.save_decrypted_shielded_outputs(
                        #[cfg(feature = "historic")]
                        masp_indexed_tx.indexed_tx,
                        &vk,
                        first_note_pos.checked_add(note_pos_offset).unwrap(),
                        note,
                        pa,
                        memo,
                    )?;
                    self.config.applied_tracker.increment_by(1);
                }
            }
        }

        self.abandon_orphaned();
        self.try_load_optional_masp_data()?;

        // NB: at this point, the wallet has been synced
        self.ctx.synced_height = *last_query_height;

        Ok(())
    }

    fn abandon_orphaned(&self) {
        self.orphaned_flag.set();
    }

    async fn perform_initial_setup(
        &mut self,
        last_query_height: Option<BlockHeight>,
        sks: &[DatedSpendingKey],
        fvks: &[DatedKeypair<ViewingKey>],
    ) -> Result<InitialState, eyre::Error> {
        debug_assert!(self.birthdays.is_empty());

        let mut min_birthday = BlockHeight(u64::MAX);

        for vk in sks
            .iter()
            .map(|esk| {
                esk.map(|k| {
                    to_viewing_key(&MaspExtendedSpendingKey::from(k)).vk
                })
            })
            .chain(fvks.iter().copied())
        {
            // NB: store the viewing keys in the wallet
            let decrypted_notes = self.ctx.pos_map.entry(vk.key).or_default();

            // NB: sanity check to confirm we haven't decrypted notes
            // before the supplied birthday
            if vk.birthday > self.ctx.synced_height
                && !decrypted_notes.is_empty()
            {
                eyre::bail!(
                    "Invalid viewing key birthday, set after notes have \
                     already been decrypted"
                );
            }

            // NB: store the birthday in order to potentially
            // save some work during trial decryptions
            self.birthdays.insert(vk.key, vk.birthday);

            // NB: the min birthday will allow skipping a bunch
            // of blocks if we are syncing from scratch
            if vk.birthday < min_birthday {
                min_birthday = vk.birthday
            }
        }

        // NB: Optimize syncing from scratch when the
        // user supplied key birthdays
        const THRESHOLD_MIN_BIRTHDAY_LOCK: u64 = 1000;

        if self.ctx.synced_height == BlockHeight(0)
            && min_birthday.0 > THRESHOLD_MIN_BIRTHDAY_LOCK
            && self.client.capabilities().may_fetch_pre_built_tree()
            && !self.birthdays.is_empty()
        {
            self.ctx.synced_height = min_birthday;
            self.spawn_first_commitment_tree(min_birthday);
        }

        let shutdown_signal = RefCell::new(&mut self.config.shutdown_signal);

        let last_block_height = Sleep {
            strategy: LinearBackoff {
                delta: Duration::from_millis(100),
            },
        }
        .run(|| async {
            if self.config.wait_for_last_query_height
                && shutdown_signal.borrow_mut().received()
            {
                return ControlFlow::Break(Err(eyre!(
                    "Interrupted while waiting for last query height",
                )));
            }

            // Query for the last produced block height
            let last_block_height = match self
                .client
                .last_block_height()
                .await
                .wrap_err("Failed to fetch last block height")
            {
                Ok(Some(last_block_height)) => last_block_height,
                Ok(None) => {
                    return if self.config.wait_for_last_query_height {
                        ControlFlow::Continue(())
                    } else {
                        ControlFlow::Break(Err(eyre!(
                            "No block has been committed yet",
                        )))
                    };
                }
                Err(err) => return ControlFlow::Break(Err(err)),
            };

            if self.config.wait_for_last_query_height
                && Some(last_block_height) < last_query_height
            {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(Ok(last_block_height))
            }
        })
        .await?;

        let last_query_height = last_query_height
            .unwrap_or(last_block_height)
            // NB: limit fetching until the last committed height
            .min(last_block_height);

        let start_height = self.ctx.synced_height.clamp(
            // NB: the wallet is initialized with height 0
            // if it hasn't synced any note, so we must clamp
            // the first height to 1 explicitly
            BlockHeight::first(),
            last_query_height,
        );

        let synced = self.ctx.synced_height == start_height
            && start_height == last_query_height;

        let initial_state = InitialState {
            synced,
            last_query_height,
            start_height,
        };

        if !synced {
            self.spawn_initial_set_of_tasks(&initial_state);

            self.client.hint(
                initial_state.start_height,
                initial_state.last_query_height,
            );

            self.config
                .scanned_tracker
                .set_upper_limit(self.cache.fetched.len() as u64);
            self.config.applied_tracker.set_upper_limit(
                self.cache.trial_decrypted.successful_decryptions() as u64,
            );
        }

        self.force_redraw_progress_bars();

        Ok(initial_state)
    }

    fn check_exit_conditions(&mut self) {
        if hints::unlikely(self.tasks.panic_flag.panicked()) {
            self.state = DispatcherState::Errored(eyre!(
                "A worker thread panicked during the shielded sync".to_string(),
            ));
        }
        if matches!(
            &self.state,
            DispatcherState::Interrupted | DispatcherState::Errored(_)
        ) {
            return;
        }
        if self.config.shutdown_signal.received() {
            self.config.fetched_tracker.message(
                "Interrupt received, shutting down shielded sync".to_string(),
            );
            self.state = DispatcherState::Interrupted;
            self.interrupt_flag.set();
        }
    }

    fn spawn_initial_set_of_tasks(&mut self, initial_state: &InitialState) {
        let needed_caps = const {
            MaspClientCapabilities::MAY_FETCH_PRE_BUILT_TREE
                .plus(MaspClientCapabilities::MAY_FETCH_PRE_BUILT_NOTE_INDEX)
                .plus(MaspClientCapabilities::MAY_FETCH_PRE_BUILT_WITNESS_MAP)
        };

        const THRESHOLD_START_OPT_MASP_DATA_FETCHES: u64 = 100;

        let meets_opt_masp_data_block_threshold =
            initial_state.last_query_height.0 - initial_state.start_height.0
                > THRESHOLD_START_OPT_MASP_DATA_FETCHES;

        if self.client.capabilities().contains(needed_caps)
            && meets_opt_masp_data_block_threshold
        {
            self.spawn_update_commitment_tree(initial_state.last_query_height);
            self.spawn_update_note_index(initial_state.last_query_height);
            self.spawn_update_witness_map(initial_state.last_query_height);

            self.fetch_state = FetchState::Fetching { left: 3usize };
        }

        let mut number_of_fetches = 0;
        let batch_size = self.config.block_batch_size;
        for from in (initial_state.start_height.0
            ..=initial_state.last_query_height.0)
            .step_by(batch_size)
        {
            let to = (from + batch_size as u64 - 1)
                .min(initial_state.last_query_height.0);
            number_of_fetches +=
                self.spawn_fetch_txs(BlockHeight(from), BlockHeight(to));
        }

        self.config
            .fetched_tracker
            .set_upper_limit(number_of_fetches);

        for (itx, tx) in self.cache.fetched.iter() {
            self.spawn_trial_decryptions(*itx, tx);
        }
    }

    fn handle_incoming_message(&mut self, message: Message) {
        match message {
            Message::FirstCommitmentTree(Ok((h, ct))) => {
                _ = self.cache.first_commitment_tree.insert((h, ct));
            }
            Message::FirstCommitmentTree(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_first_commitment_tree(height);
                }
            }
            Message::UpdateCommitmentTree(Ok((h, ct))) => {
                _ = self.cache.commitment_tree.insert((h, ct));

                self.must_decrement_left_fetching();
            }
            Message::UpdateCommitmentTree(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_update_commitment_tree(height);
                }
            }
            Message::UpdateNoteIndex(Ok((h, nm))) => {
                _ = self.cache.note_index.insert((h, nm));

                self.must_decrement_left_fetching();
            }
            Message::UpdateNoteIndex(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_update_note_index(height);
                }
            }
            Message::UpdateWitnessMap(Ok((h, wm))) => {
                _ = self.cache.witness_map.insert((h, wm));

                self.must_decrement_left_fetching();
            }
            Message::UpdateWitnessMap(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_update_witness_map(height);
                }
            }
            Message::FetchTxs(Ok((from, to, tx_batch))) => {
                for (itx, tx) in &tx_batch {
                    self.spawn_trial_decryptions(*itx, tx);
                }
                self.cache.fetched.extend(tx_batch);

                self.config.fetched_tracker.increment_by(to.0 - from.0 + 1);
                self.config
                    .scanned_tracker
                    .set_upper_limit(self.cache.fetched.len() as u64);
            }
            Message::FetchTxs(Err(TaskError {
                error,
                context: [from, to],
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_fetch_txs(from, to);
                }
            }
            Message::TrialDecrypt(itx, vk, decrypted_data) => {
                if let ControlFlow::Continue(decrypted_data) = decrypted_data {
                    self.config.applied_tracker.set_upper_limit(
                        self.config.applied_tracker.upper_limit()
                            + decrypted_data.len() as u64,
                    );
                    self.cache.trial_decrypted.insert(itx, vk, decrypted_data);
                    self.config.scanned_tracker.increment_by(1);
                }
            }
        }
    }

    /// Check if we can launch a new fetch task retry.
    fn can_launch_new_fetch_retry(&mut self, error: eyre::Error) -> bool {
        if matches!(
            self.state,
            DispatcherState::Errored(_) | DispatcherState::Interrupted
        ) {
            return false;
        }

        if self.config.retry_strategy.may_retry() {
            true
        } else {
            // NB: store last encountered error
            self.state = DispatcherState::Errored(error);
            false
        }
    }

    fn vk_synced_height(&self, vk: &ViewingKey) -> BlockHeight {
        self.birthdays
            .get(vk)
            .copied()
            .unwrap_or(self.ctx.synced_height)
    }

    fn vk_is_outdated(&self, vk: &ViewingKey, itx: &MaspIndexedTx) -> bool {
        self.vk_synced_height(vk) < itx.indexed_tx.block_height
    }

    fn try_load_optional_masp_data(&mut self) -> Result<(), eyre::Error> {
        if !self.has_optional_masp_data() {
            self.ctx.tree.as_mut().garbage_collect_ommers();
            return Ok(());
        }

        let mut witness_map = self.cache.witness_map.take().unwrap().1;
        let commitment_tree = self.cache.commitment_tree.take().unwrap().1;

        let set_of_unspent_note_pos: HashSet<_> = self
            .ctx
            .pos_map
            .values()
            .flat_map(|vk_owned_note_set| {
                vk_owned_note_set.iter().filter_map(|owned_note| {
                    if !self.ctx.spents.contains(owned_note) {
                        Some(*owned_note)
                    } else {
                        None
                    }
                })
            })
            .collect();

        // NB: Prune witnesses we don't care about
        witness_map
            .retain(|note_pos, _| set_of_unspent_note_pos.contains(note_pos));

        self.ctx.tree = BridgeTree::from_tree_and_witness_map(
            commitment_tree,
            witness_map,
        )?;

        Ok(())
    }

    #[inline(always)]
    fn has_optional_masp_data(&self) -> bool {
        matches!(&self.fetch_state, FetchState::Complete)
    }

    fn try_get_optional_masp_data(&mut self) {
        if !matches!(&self.fetch_state, FetchState::Fetching { .. }) {
            return;
        }
        while let Some(message) = self.tasks.try_recv_orphaned_message() {
            self.handle_incoming_message(message);
            std::hint::spin_loop();
        }
        // NB: Load note index as soon as we can, to avoid running
        // into errors related with unknown note positions
        if matches!(&self.fetch_state, FetchState::Fetching { left: 0usize }) {
            self.fetch_state = FetchState::Complete;
            self.ctx.note_index = self.cache.note_index.take().unwrap().1;
        }
    }

    fn must_decrement_left_fetching(&mut self) {
        let left = self.must_get_left_fetching();
        *left = left
            .checked_sub(1)
            .expect("Should not have underflowed in `must_get_left_fetching`");
    }

    fn must_get_left_fetching(&mut self) -> &mut usize {
        if let FetchState::Fetching { left } = &mut self.fetch_state {
            left
        } else {
            unreachable!("Must get `left_fetching` as `FetchState::Fetching`")
        }
    }

    fn spawn_update_witness_map(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.witness_map.as_ref(), height) {
            return;
        }
        let client = self.client.clone();
        self.spawn_async_orphaned(Box::pin(async move {
            Message::UpdateWitnessMap(
                client
                    .fetch_witness_map(height)
                    .await
                    .wrap_err("Failed to fetch witness map")
                    .map(|wm| (height, wm))
                    .map_err(|error| TaskError {
                        error,
                        context: height,
                    }),
            )
        }));
    }

    fn spawn_first_commitment_tree(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.first_commitment_tree.as_ref(), height)
        {
            return;
        }
        let client = self.client.clone();
        self.spawn_async(Box::pin(async move {
            Message::FirstCommitmentTree(
                client
                    .fetch_commitment_tree(height)
                    .await
                    .wrap_err("Failed to fetch first commitment tree")
                    .map(|ct| (height, ct))
                    .map_err(|error| TaskError {
                        error,
                        context: height,
                    }),
            )
        }));
    }

    fn spawn_update_commitment_tree(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.commitment_tree.as_ref(), height) {
            return;
        }
        let client = self.client.clone();
        self.spawn_async_orphaned(Box::pin(async move {
            Message::UpdateCommitmentTree(
                client
                    .fetch_commitment_tree(height)
                    .await
                    .wrap_err("Failed to fetch commitment tree")
                    .map(|ct| (height, ct))
                    .map_err(|error| TaskError {
                        error,
                        context: height,
                    }),
            )
        }));
    }

    fn spawn_update_note_index(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.note_index.as_ref(), height) {
            return;
        }
        let client = self.client.clone();
        self.spawn_async_orphaned(Box::pin(async move {
            Message::UpdateNoteIndex(
                client
                    .fetch_note_index(height)
                    .await
                    .wrap_err("Failed to fetch note index")
                    .map(|ni| (height, ni))
                    .map_err(|error| TaskError {
                        error,
                        context: height,
                    }),
            )
        }));
    }

    fn spawn_fetch_txs(&self, from: BlockHeight, to: BlockHeight) -> u64 {
        let mut spawned_tasks = 0;

        for [from, to] in blocks_left_to_fetch(from, to, &self.cache.fetched) {
            let client = self.client.clone();
            spawned_tasks += to.0 - from.0 + 1;
            self.spawn_async(Box::pin(async move {
                Message::FetchTxs(
                    client
                        .fetch_shielded_transfers(from, to)
                        .await
                        .wrap_err("Failed to fetch shielded transfers")
                        .map_err(|error| TaskError {
                            error,
                            context: [from, to],
                        })
                        .map(|batch| (from, to, batch)),
                )
            }));
        }

        spawned_tasks
    }

    fn spawn_trial_decryptions(&self, itx: MaspIndexedTx, tx: &Transaction) {
        for vk in self.ctx.pos_map.keys() {
            let vk_is_outdated = self.vk_is_outdated(vk, &itx);
            let tx_decrypted_in_cache =
                self.cache.trial_decrypted.get(&itx, vk).is_some();

            if vk_is_outdated && !tx_decrypted_in_cache {
                let tx = tx.clone();
                let vk = *vk;

                self.spawn_sync(move |interrupt| {
                    Message::TrialDecrypt(
                        itx,
                        vk,
                        trial_decrypt(tx, vk, || interrupt.get()),
                    )
                })
            }
        }
    }

    fn spawn_async_orphaned<F>(&self, mut fut: F)
    where
        F: Future<Output = Message> + Unpin + 'static,
    {
        let sender = self.tasks.message_sender.clone();
        let guard = (
            self.tasks.panic_flag.clone(),
            self.orphaned_flag.clone(),
            self.interrupt_flag.clone(),
        );
        self.tasks.spawner.spawn_async(async move {
            let (_panic_flag, orphaned, interrupt) = guard;
            let wrapped_fut = std::future::poll_fn(move |cx| {
                if interrupt.get() || orphaned.get() {
                    Poll::Ready(None)
                } else {
                    Pin::new(&mut fut).poll(cx).map(Some)
                }
            });
            if let Some(msg) = wrapped_fut.await {
                sender.send_async(msg).await.unwrap()
            }
        });
    }

    fn spawn_async<F>(&self, mut fut: F)
    where
        F: Future<Output = Message> + Unpin + 'static,
    {
        let sender = self.tasks.message_sender.clone();
        let guard = (
            self.tasks.active_tasks.clone(),
            self.tasks.panic_flag.clone(),
        );
        let interrupt = self.interrupt_flag.clone();
        self.tasks.spawner.spawn_async(async move {
            let _guard = guard;
            let wrapped_fut = std::future::poll_fn(move |cx| {
                if interrupt.get() {
                    Poll::Ready(None)
                } else {
                    Pin::new(&mut fut).poll(cx).map(Some)
                }
            });
            if let Some(msg) = wrapped_fut.await {
                sender.send_async(msg).await.unwrap()
            }
        });
    }

    fn spawn_sync<F>(&self, job: F)
    where
        F: FnOnce(AtomicFlag) -> Message + Send + 'static,
    {
        let sender = self.tasks.message_sender.clone();
        let guard = (
            self.tasks.active_tasks.clone(),
            self.tasks.panic_flag.clone(),
        );
        let interrupt = self.interrupt_flag.clone();
        self.tasks.spawner.spawn_sync(move || {
            let _guard = guard;
            sender.send(job(interrupt)).unwrap();
        });
    }
}

#[inline(always)]
fn pre_built_in_cache<T>(
    pre_built_data: Option<&(BlockHeight, T)>,
    desired_height: BlockHeight,
) -> bool {
    matches!(pre_built_data, Some((h, _)) if *h == desired_height)
}

#[cfg(test)]
mod dispatcher_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::hint::spin_loop;

    use futures::join;
    use namada_core::chain::BlockHeight;
    use namada_core::control_flow::testing::shutdown_signal;
    use namada_core::storage::TxIndex;
    use namada_core::task_env::TaskEnvironment;
    use namada_io::DevNullProgressBar;
    use namada_tx::IndexedTx;
    use tempfile::tempdir;

    use super::super::utils::MaspTxKind;
    use super::*;
    use crate::masp::fs::FsShieldedUtils;
    use crate::masp::test_utils::{
        TestingMaspClient, arbitrary_masp_tx,
        arbitrary_masp_tx_with_fee_unshielding, arbitrary_vk,
        dated_arbitrary_vk,
    };
    use crate::masp::utils::MaspIndexedTx;
    use crate::masp::{MaspLocalTaskEnv, ShieldedSyncConfig};

    #[tokio::test]
    async fn test_applying_cache_drains_decrypted_data() {
        let (client, _) = TestingMaspClient::new(BlockHeight::first());
        let (_sender, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .client(client)
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .build();
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let mut dispatcher = config.dispatcher(s, &utils).await;
                dispatcher
                    .ctx
                    .pos_map
                    .insert(arbitrary_vk(), BTreeSet::new());
                // fill up the dispatcher's cache
                for h in 1u64..10 {
                    let itx = MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: h.into(),
                            block_index: Default::default(),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    };
                    dispatcher.cache.fetched.insert((itx, arbitrary_masp_tx()));
                    dispatcher.ctx.note_index.insert(itx, NotePosition(h));
                    dispatcher.cache.trial_decrypted.insert(
                        itx,
                        arbitrary_vk(),
                        BTreeMap::new(),
                    )
                }

                dispatcher
                    .apply_cache_to_shielded_context(&InitialState {
                        synced: false,
                        start_height: BlockHeight::first(),
                        last_query_height: 9.into(),
                    })
                    .expect("Test failed");
                assert!(dispatcher.cache.fetched.is_empty());
                assert!(dispatcher.cache.trial_decrypted.is_empty());
                assert_eq!(
                    HashMap::from([(arbitrary_vk(), BTreeSet::new())]),
                    dispatcher.ctx.pos_map
                );
                assert_eq!(BlockHeight(9), dispatcher.ctx.synced_height);
            })
            .await;
    }

    #[tokio::test]
    async fn test_async_counter_on_async_interrupt() {
        MaspLocalTaskEnv::new(1)
            .expect("Test failed")
            .run(|spawner| async move {
                let active_tasks = AsyncCounter::new();
                let interrupt = {
                    let int = AtomicFlag::default();

                    // preemptively set the task to an
                    // interrupted state
                    int.set();

                    int
                };

                // clone the active tasks handle,
                // to increment its internal ref count
                let guard = active_tasks.clone();

                let mut never_yielding_future = Box::pin(async move {
                    let _guard = guard;

                    // this future never yields, so the only
                    // way to early exit is to be interrupted
                    // through the wrapped future
                    std::future::pending::<()>().await;
                });
                let interruptable_future = std::future::poll_fn(move |cx| {
                    if interrupt.get() {
                        // early exit here, by checking the interrupt state,
                        // which we immediately set above
                        Poll::Ready(())
                    } else {
                        Pin::new(&mut never_yielding_future).poll(cx)
                    }
                });

                spawner.spawn_async(interruptable_future);

                // sync with the spawned future by waiting
                // for the active tasks counter to reach zero
                active_tasks.await;
            })
            .await;
    }

    /// This test checks that a (sync / async) thread panicking
    /// * allows existing tasks to finish,
    /// * sets the panic flag
    /// * dispatcher returns the expected error
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_panic_flag() {
        test_panic_flag_aux(true).await;
        test_panic_flag_aux(false).await;
    }

    async fn test_panic_flag_aux(sync: bool) {
        let (client, _) = TestingMaspClient::new(BlockHeight::first());
        let (_sender, shutdown_signal) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_signal)
            .client(client)
            .build();
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        _ = MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let dispatcher = config.dispatcher(s, &utils).await;

                let barrier = Arc::new(tokio::sync::Barrier::new(11));
                for _ in 0..10 {
                    let barrier = barrier.clone();
                    dispatcher.spawn_async(Box::pin(async move {
                        barrier.wait().await;
                        Message::FetchTxs(Err(TaskError {
                            error: eyre!("Test"),
                            context: [
                                BlockHeight::first(),
                                BlockHeight::first(),
                            ],
                        }))
                    }));
                }
                assert!(!dispatcher.tasks.panic_flag.panicked());
                // panic a thread
                if sync {
                    dispatcher.spawn_sync(|_| panic!("OH NOES!"));
                } else {
                    dispatcher
                        .spawn_async(Box::pin(async { panic!("OH NOES!") }));
                }

                // run the dispatcher
                let flag = dispatcher.tasks.panic_flag.clone();
                let esks = [DatedSpendingKey::new(
                    MaspExtendedSpendingKey::master(b"bing bong").into(),
                    None,
                )];
                let dispatcher_fut =
                    dispatcher.run(Some(BlockHeight(10)), &esks, &[]);

                // we poll the dispatcher future until the panic thread has
                // panicked.
                let wanker = Arc::new(AtomicWaker::new());
                let _ = {
                    let flag = flag.clone();
                    let wanker = wanker.clone();
                    std::thread::spawn(move || {
                        while !flag.panicked() {
                            spin_loop();
                        }
                        wanker.wake()
                    })
                };
                let panicked_fut = std::future::poll_fn(move |cx| {
                    if flag.panicked() {
                        Poll::Ready(())
                    } else {
                        wanker.register(cx.waker());
                        Poll::Pending
                    }
                });

                // we assert that the panic thread panicked and retrieve the
                // dispatcher future
                let fut = match select(
                    Box::pin(dispatcher_fut),
                    Box::pin(panicked_fut),
                )
                .await
                {
                    Either::Right((_, fut)) => fut,
                    Either::Left((res, _)) => panic!("Test failed: {res:?}"),
                };

                let (_, res) = join!(barrier.wait(), fut);

                let Err(msg) = res else { panic!("Test failed") };

                assert_eq!(
                    msg.to_string(),
                    "A worker thread panicked during the shielded sync",
                );
            })
            .await;
    }

    /// We test that if a masp transaction is only partially trial-decrypted
    /// before the process is interrupted, we discard the partial results.
    #[test]
    fn test_discard_partial_decryption() {
        let tx = arbitrary_masp_tx_with_fee_unshielding();
        let vk = arbitrary_vk();
        let guard = AtomicFlag::default();
        let interrupt = || {
            if guard.get() {
                true
            } else {
                guard.set();
                false
            }
        };
        let res = trial_decrypt(tx, vk, interrupt);
        assert_eq!(res, ControlFlow::Break(()));
    }

    /// Test that if fetching fails before finishing,
    /// we re-establish the fetching process
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_retry_fetch() {
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        let (client, masp_tx_sender) = TestingMaspClient::new(2.into());
        let (_send, shutdown_sig) = shutdown_signal();
        let mut config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .build();
        let vk = dated_arbitrary_vk();

        // we first test that with no retries, a fetching failure
        // stops process
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                masp_tx_sender.send(None).expect("Test failed");
                let dispatcher = config.clone().dispatcher(s, &utils).await;

                let result = dispatcher.run(None, &[], &[vk]).await;
                match result {
                    Err(msg) => assert_eq!(
                        msg.to_string(),
                        "Failed to fetch shielded transfers"
                    ),
                    other => {
                        panic!("{:?} does not match Error::Other(_)", other)
                    }
                }
            })
            .await;

        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                // We now have a fetch failure followed by two successful
                // masp txs from the same block.
                let masp_tx = arbitrary_masp_tx();
                masp_tx_sender.send(None).expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 1.into(),
                                block_index: TxIndex(1),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 1.into(),
                                block_index: TxIndex(2),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                config.retry_strategy = RetryStrategy::Times(1);
                let dispatcher = config.dispatcher(s, &utils).await;
                // This should complete successfully
                let ctx = dispatcher
                    .run(None, &[], &[vk])
                    .await
                    .expect("Test failed")
                    .expect("Test failed");
                let keys =
                    ctx.note_index.keys().cloned().collect::<BTreeSet<_>>();
                let expected = BTreeSet::from([
                    MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: 1.into(),
                            block_index: TxIndex(1),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    },
                    MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: 1.into(),
                            block_index: TxIndex(2),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    },
                ]);

                assert_eq!(keys, expected);
                assert_eq!(ctx.synced_height, BlockHeight(2));
                assert_eq!(ctx.note_map.len(), 2);
            })
            .await;
    }

    /// Test that if we don't scan all fetched notes, they
    /// are persisted in a cache
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_unscanned_cache() {
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        let (client, masp_tx_sender) = TestingMaspClient::new(3.into());
        let (_send, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .block_batch_size(1)
            .build();

        let vk = dated_arbitrary_vk();
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let dispatcher = config.clone().dispatcher(s, &utils).await;

                let masp_tx = arbitrary_masp_tx();
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 1.into(),
                                block_index: TxIndex(1),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 1.into(),
                                block_index: TxIndex(2),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                masp_tx_sender.send(None).expect("Test failed");
                let result = dispatcher.run(None, &[], &[vk]).await;
                match result {
                    Err(msg) => assert_eq!(
                        msg.to_string(),
                        "Failed to fetch shielded transfers"
                    ),
                    other => {
                        panic!("{:?} does not match Error::Other(_)", other)
                    }
                }
                let cache = utils.cache_load().await.expect("Test failed");
                let expected = BTreeMap::from([
                    (
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 1.into(),
                                block_index: TxIndex(1),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    ),
                    (
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 1.into(),
                                block_index: TxIndex(2),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    ),
                ]);
                assert_eq!(cache.fetched.txs, expected);
            })
            .await;
    }

    /// Test that we can successfully interrupt the dispatcher
    /// and that it cleans up after itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_interrupt() {
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        let (client, masp_tx_sender) = TestingMaspClient::new(2.into());
        let (send, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .block_batch_size(2)
            .build();

        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let dispatcher = config.clone().dispatcher(s, &utils).await;

                // we expect a batch of two blocks, but we only send one
                let masp_tx = arbitrary_masp_tx();
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 1.into(),
                                block_index: TxIndex(1),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");

                send.send_replace(true);
                let res = dispatcher
                    .run(None, &[], &[dated_arbitrary_vk()])
                    .await
                    .expect("Test failed");
                assert!(res.is_none());

                let DispatcherCache {
                    first_commitment_tree,
                    commitment_tree,
                    witness_map,
                    note_index,
                    fetched,
                    trial_decrypted,
                } = utils.cache_load().await.expect("Test failed");
                assert!(first_commitment_tree.is_none());
                assert!(commitment_tree.is_none());
                assert!(witness_map.is_none());
                assert!(note_index.is_none());
                assert!(fetched.is_empty());
                assert!(trial_decrypted.is_empty());
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_key_birthdays() {
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        let (client, _masp_tx_sender) = TestingMaspClient::new(3.into());
        let (_send, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .block_batch_size(1)
            .build();

        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let mut dispatcher = config.clone().dispatcher(s, &utils).await;

                let vk = arbitrary_vk();

                fn itx(block_height: BlockHeight) -> MaspIndexedTx {
                    MaspIndexedTx {
                        kind: MaspTxKind::Transfer,
                        indexed_tx: IndexedTx {
                            block_height,
                            block_index: TxIndex(0),
                            batch_index: None,
                        },
                    }
                }

                dispatcher.ctx.synced_height = BlockHeight(123);
                dispatcher.birthdays.insert(vk, BlockHeight(456));
                assert!(
                    !dispatcher.vk_is_outdated(&vk, &itx(BlockHeight(300)))
                );

                dispatcher.birthdays.insert(vk, BlockHeight(6));
                assert!(dispatcher.vk_is_outdated(&vk, &itx(BlockHeight(300))));

                dispatcher.birthdays.swap_remove(&vk);
                assert!(dispatcher.vk_is_outdated(&vk, &itx(BlockHeight(300))));
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_no_blocks_to_sync() {
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        let (client, _masp_tx_sender) = TestingMaspClient::new(3.into());
        let (_send, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .block_batch_size(1)
            .build();

        MaspLocalTaskEnv::new(2)
            .expect("Test failed")
            .run(|s| async {
                let mut dispatcher = config.clone().dispatcher(s, &utils).await;
                dispatcher.ctx.synced_height = BlockHeight(3);
                let initial_state = dispatcher
                    .perform_initial_setup(None, &[], &[dated_arbitrary_vk()])
                    .await
                    .unwrap();
                assert!(initial_state.synced);
            })
            .await;

        MaspLocalTaskEnv::new(2)
            .expect("Test failed")
            .run(|s| async {
                let mut dispatcher = config.clone().dispatcher(s, &utils).await;
                dispatcher.ctx.synced_height = BlockHeight(2);
                let initial_state = dispatcher
                    .perform_initial_setup(None, &[], &[dated_arbitrary_vk()])
                    .await
                    .unwrap();
                assert!(!initial_state.synced);
            })
            .await;
    }
}
