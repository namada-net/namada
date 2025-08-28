//! The shielded wallet implementation

use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::fmt;

use eyre::{ContextCompat, WrapErr, eyre};
use masp_primitives::asset_type::AssetType;
#[cfg(feature = "mainnet")]
use masp_primitives::consensus::MainNetwork as Network;
#[cfg(not(feature = "mainnet"))]
use masp_primitives::consensus::TestNetwork as Network;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::ff::PrimeField;
use masp_primitives::memo::MemoBytes;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::{
    Diversifier, Node, Note, Nullifier, ViewingKey,
};
use masp_primitives::transaction::builder::Builder;
use masp_primitives::transaction::components::sapling::builder::BuildParams;
use masp_primitives::transaction::components::{
    I128Sum, TxOut, U64Sum, ValueSum,
};
use masp_primitives::transaction::fees::fixed::FeeRule;
use masp_primitives::transaction::{Transaction, builder};
use masp_primitives::zip32::{ExtendedKey, PseudoExtendedKey};
use namada_core::address::Address;
use namada_core::arith::{CheckedAdd, CheckedMul, CheckedSub, checked};
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::chain::BlockHeight;
use namada_core::collections::{HashMap, HashSet};
use namada_core::control_flow;
use namada_core::masp::{
    AssetData, MaspEpoch, TransferSource, TransferTarget, encode_asset_type,
};
use namada_core::task_env::TaskEnvironment;
use namada_core::time::{DateTimeUtc, DurationSecs};
use namada_core::token::{
    Amount, Change, DenominatedAmount, Denomination, MaspDigitPos,
};
use namada_core::uint::I256;
use namada_io::client::Client;
use namada_io::{
    Io, MaybeSend, MaybeSync, NamadaIo, ProgressBar, display_line,
    edisplay_line,
};
use namada_wallet::{DatedKeypair, DatedSpendingKey};
use rand::prelude::StdRng;
use rand_core::{OsRng, SeedableRng};

use super::utils::{MaspIndexedTx, TrialDecrypted};
use crate::masp::bridge_tree::BridgeTree;
use crate::masp::utils::MaspClient;
use crate::masp::wallet_migrations::VersionedWalletRef;
use crate::masp::{
    ContextSyncStatus, Conversions, MaspAmount, MaspDataLogEntry, MaspFeeData,
    MaspTransferData, MaspTxCombinedData, NETWORK, NoteIndex,
    ShieldedSyncConfig, ShieldedTransfer, ShieldedUtils, SpentNotesTracker,
    TransferErr, WalletMap,
};
#[cfg(any(test, feature = "testing"))]
use crate::masp::{ENV_VAR_MASP_TEST_SEED, testing};

/// Type  for the response we get from
/// querying conversions
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ConversionData {
    token: Address,
    denomination: Denomination,
    digit_pos: MaspDigitPos,
    epoch: MaspEpoch,
    conversion: I128Sum,
    merkle_path: MerklePath<Node>,
}

impl
    From<(
        Address,
        Denomination,
        MaspDigitPos,
        MaspEpoch,
        I128Sum,
        MerklePath<Node>,
    )> for ConversionData
{
    fn from(
        value: (
            Address,
            Denomination,
            MaspDigitPos,
            MaspEpoch,
            I128Sum,
            MerklePath<Node>,
        ),
    ) -> Self {
        ConversionData {
            token: value.0,
            denomination: value.1,
            digit_pos: value.2,
            epoch: value.3,
            conversion: value.4,
            merkle_path: value.5,
        }
    }
}

/// A conversions cache
#[derive(Clone, Default, BorshSerialize, BorshDeserialize, Debug)]
pub struct EpochedConversions {
    /// A set of cached conversions
    pub inner: BTreeMap<AssetType, ConversionData>,
    /// Masp epoch for which these conversions are valid
    pub epoch: MaspEpoch,
}

/// Position of a note in the commitment tree.
///
/// This value corresponds to the number of leaf nodes in the
/// tree before the current note.
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
)]
pub struct NotePosition(pub u64);

impl From<u64> for NotePosition {
    #[inline]
    fn from(pos: u64) -> Self {
        Self(pos)
    }
}

impl From<NotePosition> for u64 {
    #[inline]
    fn from(NotePosition(pos): NotePosition) -> u64 {
        pos
    }
}

impl From<NotePosition> for crate::masp::bridge_tree::pkg::Position {
    #[inline]
    fn from(NotePosition(pos): NotePosition) -> Self {
        Self::from(pos)
    }
}

impl NotePosition {
    #[allow(missing_docs)]
    pub fn checked_add<T: TryInto<u64>>(self, other: T) -> Option<Self> {
        let other = other.try_into().ok()?;
        Some(Self(self.0.checked_add(other)?))
    }

    #[allow(missing_docs)]
    pub fn checked_sub<T: TryInto<u64>>(self, other: T) -> Option<Self> {
        let other = other.try_into().ok()?;
        Some(Self(self.0.checked_sub(other)?))
    }
}

impl fmt::Display for NotePosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents the current state of the shielded pool from the perspective of
/// the chosen viewing keys.
#[derive(BorshSerialize, BorshDeserialize, Debug, Default)]
pub struct ShieldedWallet<U: ShieldedUtils> {
    /// Location where this shielded context is saved
    #[borsh(skip)]
    pub utils: U,
    /// The commitment tree produced by scanning all transactions in the MASP
    pub tree: BridgeTree,
    /// Maps viewing keys to the block height to which they are synced.
    /// In particular, the height given by the value *has been scanned*.
    pub vk_heights: BTreeMap<ViewingKey, Option<MaspIndexedTx>>,
    /// The set of note positions that have been spent
    pub spents: HashSet<NotePosition>,
    /// Maps viewing keys to applicable note positions
    ///
    /// The inner set includes notes that have already been spent
    pub pos_map: HashMap<ViewingKey, BTreeSet<NotePosition>>,
    /// Maps a nullifier to the note position to which it applies
    pub nf_map: HashMap<Nullifier, NotePosition>,
    /// Maps note positions to their corresponding notes
    pub note_map: HashMap<NotePosition, Note>,
    /// Maps note positions to their corresponding memos
    pub memo_map: HashMap<NotePosition, MemoBytes>,
    /// Maps note positions to the diversifier of their payment address
    pub div_map: HashMap<NotePosition, Diversifier>,
    /// Maps asset types to their decodings
    pub asset_types: HashMap<AssetType, AssetData>,
    /// A conversions cache
    pub conversions: EpochedConversions,
    /// Maps a shielded tx to the index of its first output note.
    pub note_index: NoteIndex,
    /// The sync state of the context
    pub sync_status: ContextSyncStatus,
<<<<<<< HEAD
=======
    /// Maps note positions to their corresponding viewing keys
    #[cfg(feature = "historic")]
    pub vk_map: HashMap<NotePosition, ViewingKey>,
    /// The history of the applied shielded transactions (the failed ones won't
    /// show up in here). Only the sapling bundle data is cached here, for the
    /// transparent bundle data one should rely on querying a node or an
    /// indexer
    #[cfg(feature = "historic")]
    pub history: HashMap<ViewingKey, HashMap<IndexedTx, TxHistoryEntry>>,
>>>>>>> 7c7c74501 (Drop unused vk_map field in shielded wallet)
}

<<<<<<< HEAD
/// Default implementation to ease construction of TxContexts. Derive cannot be
/// used here due to CommitmentTree not implementing Default.
impl<U: ShieldedUtils + Default> Default for ShieldedWallet<U> {
    fn default() -> ShieldedWallet<U> {
        ShieldedWallet::<U> {
            utils: U::default(),
            vk_heights: BTreeMap::new(),
            note_index: BTreeMap::default(),
            tree: BridgeTree::empty(),
            note_map: HashMap::default(),
            pos_map: HashMap::default(),
            nf_map: HashMap::default(),
            memo_map: HashMap::default(),
            div_map: HashMap::default(),
            spents: HashSet::default(),
            conversions: Default::default(),
            asset_types: HashMap::default(),
            vk_map: HashMap::default(),
            sync_status: ContextSyncStatus::Confirmed,
        }
    }
=======
/// The data for an indexed masp transaction
#[derive(BorshSerialize, BorshDeserialize, Debug, Default)]
pub struct TxHistoryEntry {
    /// The inputs of the indexed transaction
    pub inputs: HashMap<Address, Amount>,
    /// The outputs of the indexed transaction
    pub outputs: HashMap<Address, Amount>,
    /// A flag to mark the presence of conversions in the transaction
    pub conversions: bool,
>>>>>>> a3f44a9c0 (Derive default on shielded wallet)
}

impl<U: ShieldedUtils + MaybeSend + MaybeSync> ShieldedWallet<U> {
    /// Try to load the last saved shielded wallet from the given context
    /// directory. If the file is missing, an empty wallet is created.
    /// Otherwise, we load the wallet and attempt to migrate it to the
    /// latest version. This function panics if that fails.
    pub async fn load(&mut self) {
        self.utils.clone().load(self, false).await.unwrap()
    }

    /// Same as the load function, but is provided an async closure
    /// as an error handler. This is useful for calling this function
    /// from non-CLI frontends.
    pub async fn try_load<F, X>(&mut self, on_error: F)
    where
        F: Fn(std::io::Error) -> X,
        X: std::future::Future<Output = ()>,
    {
        if let Err(e) = self.utils.clone().load(self, false).await {
            on_error(e).await;
        }
    }

    /// Try to load the last saved confirmed shielded context from the given
    /// context directory.If the file is missing, an empty wallet is created.
    /// Otherwise, we load the wallet and attempt to migrate it to the
    /// latest version. This function panics if that fails.
    pub async fn load_confirmed(&mut self) {
        self.utils.clone().load(self, true).await.unwrap()
    }

    /// Save this shielded context into its associated context directory. If the
    /// state to be saved is confirmed than also delete the speculative one (if
    /// available)
    pub async fn save(&self) -> std::io::Result<()> {
        self.utils
            .save(VersionedWalletRef::V2(self), self.sync_status)
            .await
    }

    /// Update the merkle tree of witnesses the first time we
    /// scan new MASP transactions.
    pub(crate) fn update_witnesses(
        &mut self,
        masp_indexed_tx: MaspIndexedTx,
        shielded: &Transaction,
        trial_decrypted: &TrialDecrypted,
    ) -> Result<(), eyre::Error> {
        let mut note_pos = NotePosition(self.tree.as_ref().tree_size());

        self.note_index.insert(masp_indexed_tx, note_pos);

        for so in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_outputs)
        {
            // Create merkle tree leaf node from note commitment
            let node = Node::new(so.cmu.to_repr());

            // Append the node to the tree
            self.tree
                .as_mut()
                .append(node)
                .wrap_err("failed to append to note commitment tree")?;

            if trial_decrypted.decrypted_by_any_vk(&masp_indexed_tx) {
                // Finally, make it easier to construct merkle paths to this new
                // note that we own
                eyre::ensure!(
                    self.tree.as_mut().mark().is_some(),
                    "could not mark node as a witness"
                );
            }

            checked!(note_pos += 1u64).unwrap();
        }

        Ok(())
    }

    /// Sync the current state of the multi-asset shielded pool in a
    /// ShieldedContext with the state on-chain.
    pub async fn sync<M, T, I>(
        &mut self,
        env: impl TaskEnvironment,
        config: ShieldedSyncConfig<M, T, I>,
        last_query_height: Option<BlockHeight>,
        sks: &[DatedSpendingKey],
        fvks: &[DatedKeypair<ViewingKey>],
    ) -> Result<(), eyre::Error>
    where
        M: MaspClient + Send + Sync + Unpin + 'static,
        T: ProgressBar,
        I: control_flow::ShutdownSignal,
    {
        env.run(|spawner| async move {
            let dispatcher = config.dispatcher(spawner, &self.utils).await;

            if let Some(updated_ctx) =
                dispatcher.run(None, last_query_height, sks, fvks).await?
            {
                *self = updated_ctx;
            }

            Ok(())
        })
        .await
    }

    pub(crate) fn min_height_to_sync_from(
        &self,
    ) -> Result<BlockHeight, eyre::Error> {
        let Some(maybe_least_synced_vk_height) =
            self.vk_heights.values().min().cloned()
        else {
            return Err(eyre!(
                "No viewing keys are available in the shielded context to \
                 decrypt notes with"
                    .to_string(),
            ));
        };
        Ok(maybe_least_synced_vk_height
            .map_or_else(BlockHeight::first, |itx| itx.indexed_tx.block_height))
    }

    #[allow(missing_docs)]
    pub fn save_decrypted_shielded_outputs(
        &mut self,
        vk: &ViewingKey,
        note_pos: NotePosition,
        note: Note,
        pa: masp_primitives::sapling::PaymentAddress,
        memo: MemoBytes,
    ) -> Result<(), eyre::Error> {
        // Add this note to list of notes decrypted by this
        // viewing key
        self.pos_map.entry(*vk).or_default().insert(note_pos);
<<<<<<< HEAD
        // Compute the nullifier now to quickly recognize when
        // spent
        let nf = note.nf(
            &vk.nk,
            note_pos
                .try_into()
                .map_err(|_| eyre!("Can not get nullifier".to_string()))?,
        );
=======
        // Compute the nullifier now to quickly recognize when spent
        let nf = note.nf(&vk.nk, note_pos.into());
>>>>>>> b69a0ae8e (Use domain type for note positions)
        self.note_map.insert(note_pos, note);
        if !is_empty_memo(&memo) {
            self.memo_map.insert(note_pos, memo);
        }
        // The payment address' diversifier is required to spend
        // note
        self.div_map.insert(note_pos, *pa.diversifier());
        self.nf_map.insert(nf, note_pos);
<<<<<<< HEAD
        self.vk_map.insert(note_pos, *vk);
=======
        #[cfg(feature = "historic")]
        {
            self.vk_map.insert(note_pos, *vk);

            // Update the history
            let asset_data = self
                .asset_types
                .get(&note.asset_type)
                .ok_or_else(|| eyre!("Can not get the asset data"))?
                .to_owned();
            let output_entry = self
                .history
                .entry(vk.to_owned())
                .or_default()
                .entry(indexed_tx)
                .or_default()
                .outputs
                .entry(asset_data.token)
                .or_insert(Amount::zero());
            // No need to take care of the denomination as that should already
            // be the default one for the given token
            let note_amount =
                Amount::from_masp_denominated(note.value, asset_data.position);

            *output_entry = checked!(output_entry + note_amount)
                .wrap_err("Overflow in shielded history outputs")?;
        }

>>>>>>> 7c7c74501 (Drop unused vk_map field in shielded wallet)
        Ok(())
    }

    #[allow(missing_docs)]
    pub fn save_shielded_spends(
        &mut self,
        transaction: &Transaction,
<<<<<<< HEAD
        update_witness_map: bool,
    ) {
=======
        #[cfg(feature = "historic")] update_history: Option<IndexedTx>,
    ) -> Result<(), eyre::Error> {
        #[cfg(feature = "historic")]
        let used_conversions = transaction
            .sapling_bundle()
            .is_some_and(|bundle| !bundle.shielded_converts.is_empty());

>>>>>>> f7ef28fd4 (Build MASP witnesses locally)
        for ss in transaction
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_spends)
        {
            // If the shielded spend's nullifier is in our map, then target
            // note is rendered unusable
<<<<<<< HEAD
<<<<<<< HEAD
            if let Some(note_pos) = self.nf_map.get(&ss.nullifier) {
                self.spents.insert(*note_pos);
                if update_witness_map {
                    self.witness_map.swap_remove(note_pos);
=======
            if let Some(note_pos) = self.nf_map.get(&ss.nullifier).copied() {
=======
            if let Some(note_pos) = self.nf_map.swap_remove(&ss.nullifier) {
                self.div_map.swap_remove(&note_pos);
                self.note_map.swap_remove(&note_pos);
>>>>>>> 8348a34d2 (Remove unnecessary data from shielded wallet)
                self.spents.insert(note_pos);
                self.tree
                    .as_mut()
                    .remove_mark(note_pos.into())
                    .unwrap_or_else(|err| {
                        panic!("Failed to remove marked leaf: {err}")
                    });

                #[cfg(feature = "historic")]
                {
                    // Update the history if required
                    if let Some(indexed_tx) = update_history {
                        let vk =
                            self.vk_map.get(&note_pos).ok_or_else(|| {
                                eyre!(
                                    "Missing viewing key for the provided \
                                     note position"
                                )
                            })?;
                        let note =
                            self.note_map.get(&note_pos).ok_or_else(|| {
                                eyre!(
                                    "Missing note for the provided note \
                                     position"
                                )
                            })?;
                        let asset_data = self
                            .asset_types
                            .get(&note.asset_type)
                            .ok_or_else(|| eyre!("Can not get the asset data"))?
                            .to_owned();

                        let history_entry = self
                            .history
                            .entry(vk.to_owned())
                            .or_default()
                            .entry(indexed_tx)
                            .or_default();
                        history_entry.conversions = used_conversions;

                        let input_entry = history_entry
                            .inputs
                            .entry(asset_data.token)
                            .or_insert(Amount::zero());
                        // No need to take care of the denomination as that
                        // should already be the default
                        // one for the given token
                        let note_amount = Amount::from_masp_denominated(
                            note.value,
                            asset_data.position,
                        );
                        *input_entry = checked!(input_entry + note_amount)
                            .wrap_err("Overflow in shielded history inputs")?;
                    }
>>>>>>> f7ef28fd4 (Build MASP witnesses locally)
                }
            }
        }
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    pub async fn compute_shielded_balance(
        &mut self,
        vk: &ViewingKey,
    ) -> Result<Option<I128Sum>, eyre::Error> {
        // Cannot query the balance of a key that's not in the map
        if !self.pos_map.contains_key(vk) {
            return Ok(None);
        }
        let mut val_acc = I128Sum::zero();
        // Retrieve the notes that can be spent by this key
        if let Some(avail_notes) = self.pos_map.get(vk) {
            for note_idx in avail_notes {
                // Spent notes cannot contribute a new transaction's pool
                if self.spents.contains(note_idx) {
                    continue;
                }
                // Get note associated with this ID
                let note = self
                    .note_map
                    .get(note_idx)
                    .ok_or_else(|| eyre!("Unable to get note {note_idx}"))?;
                // Finally add value to multi-asset accumulator
                val_acc += I128Sum::from_nonnegative(
                    note.asset_type,
                    i128::from(note.value),
                )
                .map_err(|()| {
                    eyre!("found note with invalid value or asset type")
                })?
            }
        }
        Ok(Some(val_acc))
    }

    /// Try to convert as much of the given asset type-value pair using the
    /// given allowed conversion. Usage is incremented by the amount of the
    /// conversion used, the conversions are applied to the given input, and
    /// the trace amount that could not be converted is moved from input to
    /// output.
    #[allow(clippy::too_many_arguments)]
    async fn apply_conversion(
        &mut self,
        io: &impl Io,
        conv: AllowedConversion,
        asset_type: AssetType,
        value: i128,
        usage: &mut I128Sum,
        input: &mut I128Sum,
        output: &mut I128Sum,
    ) -> Result<(), eyre::Error> {
        // We do not need to convert negative values
        if value <= 0 {
            return Ok(());
        }
        // If conversion is possible, accumulate the exchanged amount
        let conv: I128Sum = I128Sum::from_sum(conv.into());
        // The amount required of current asset to qualify for conversion
        let threshold = -conv[&asset_type];
        if threshold == 0 {
            edisplay_line!(
                io,
                "Asset threshold of selected conversion for asset type {} is \
                 0, this is a bug, please report it.",
                asset_type
            );
            eyre::bail!("Conversion asset threshold cannot be null");
        }
        // We should use an amount of the AllowedConversion that almost
        // cancels the original amount
        let required = value / threshold;
        // Forget about the trace amount left over because we cannot
        // realize its value
        let trace = I128Sum::from_pair(asset_type, value % threshold);
        match checked!(input + &(conv * &required) - &trace) {
            // If applying the conversion does not overflow or result in
            // negative input
            Ok(new_input) if new_input >= I128Sum::zero() => {
                // Record how much more of the given conversion has been used
                *usage += ValueSum::from_pair(asset_type, required);
                // Apply conversions to input and move trace amount to output
                *input = new_input;
                *output += trace;
            }
            _ => {
                // Otherwise don't apply the conversion and simply move value
                // over to output
                let comp = I128Sum::from_pair(asset_type, value);
                *output += comp.clone();
                *input -= comp;
            }
        }
        Ok(())
    }

    /// Updates the internal state with the data of the newly generated
    /// transaction. More specifically invalidate the spent notes, but do not
    /// cache the newly produced output descriptions and therefore the merkle
    /// tree (this is because we don't know the exact position in the tree where
    /// the new notes will be appended)
    pub async fn pre_cache_transaction(
        &mut self,
        masp_tx: &Transaction,
    ) -> Result<(), eyre::Error> {
<<<<<<< HEAD
        self.save_shielded_spends(masp_tx, false);
=======
        self.save_shielded_spends(
            masp_tx,
            #[cfg(feature = "historic")]
            None,
        )?;
>>>>>>> f7ef28fd4 (Build MASP witnesses locally)

        // Save the speculative state for future usage
        self.sync_status = ContextSyncStatus::Speculative;
        self.save().await.map_err(|e| eyre!(e.to_string()))?;

        Ok(())
    }
}

/// A trait that allows downstream types specify how a shielded wallet
/// should interact / query a node.
pub trait ShieldedQueries<U: ShieldedUtils + MaybeSend + MaybeSync>:
    std::ops::Deref<Target = ShieldedWallet<U>> + std::ops::DerefMut
{
    /// Get the address of the native token
    #[allow(async_fn_in_trait)]
    async fn query_native_token<C: Client + Sync>(
        client: &C,
    ) -> Result<Address, eyre::Error>;

    /// Query the denomination of a token type
    #[allow(async_fn_in_trait)]
    async fn query_denom<C: Client + Sync>(
        client: &C,
        token: &Address,
    ) -> Option<Denomination>;

    /// Query for converting assets across epochs
    #[allow(async_fn_in_trait)]
    async fn query_conversion<C: Client + Sync>(
        client: &C,
        asset_type: AssetType,
    ) -> Option<(
        Address,
        Denomination,
        MaspDigitPos,
        MaspEpoch,
        I128Sum,
        MerklePath<Node>,
    )>;

    /// A cached version of `query_conversion`. The cache
    /// gets cleared when the Masp epoch changes.
    #[allow(async_fn_in_trait)]
    async fn get_conversion<C: Client + Sync>(
        client: &C,
        asset_type: AssetType,
        cache: &mut EpochedConversions,
    ) -> Option<ConversionData> {
        match cache.inner.get(&asset_type).cloned() {
            None => {
                let res: ConversionData =
                    Self::query_conversion(client, asset_type).await?.into();
                cache.inner.insert(asset_type, res.clone());
                Some(res)
            }
            some => some,
        }
    }

    /// Get the last block height
    #[allow(async_fn_in_trait)]
    async fn query_block<C: Client + Sync>(
        client: &C,
    ) -> Result<Option<u64>, eyre::Error>;

    /// Get the upper limit on the time to make a new block
    #[allow(async_fn_in_trait)]
    async fn query_max_block_time_estimate<C: Client + Sync>(
        client: &C,
    ) -> Result<DurationSecs, eyre::Error>;

    /// Query the MASP epoch
    #[allow(async_fn_in_trait)]
    async fn query_masp_epoch<C: Client + Sync>(
        client: &C,
    ) -> Result<MaspEpoch, eyre::Error>;
}

///  The methods of the shielded wallet that depend on the [`ShieldedQueries`]
/// trait. These cannot be overridden downstream.
pub trait ShieldedApi<U: ShieldedUtils + MaybeSend + MaybeSync>:
    ShieldedQueries<U>
{
    /// A method that loads the wallet and empties the conversion cache if the
    /// masp epoch has advanced.
    #[allow(async_fn_in_trait)]
    async fn load_with_caching<C: Client + Sync>(
        &mut self,
        client: &C,
    ) -> Result<(), eyre::Error> {
        self.load().await;
        let epoch = Self::query_masp_epoch(client).await?;
        if self.conversions.epoch < epoch {
            self.conversions.epoch = epoch;
            self.conversions.inner.clear();
        }
        Ok(())
    }
    /// Use the addresses already stored in the wallet to precompute as many
    /// asset types as possible.
    #[allow(async_fn_in_trait)]
    async fn precompute_asset_types<C: Client + Sync>(
        &mut self,
        client: &C,
        tokens: BTreeSet<&Address>,
    ) -> Result<(), eyre::Error> {
        // To facilitate lookups of human-readable token names
        for token in tokens {
            // check if token is already in the cache
            if self.asset_types.values().any(|ass| ass.token == *token) {
                continue;
            }
            let Some(denom) = Self::query_denom(client, token).await else {
                return Err(eyre!("denomination for token {token}"));
            };
            for position in MaspDigitPos::iter() {
                let asset_type =
                    encode_asset_type(token.clone(), denom, position, None)
                        .map_err(|_| eyre!("unable to create asset type",))?;
                self.asset_types.insert(
                    asset_type,
                    AssetData {
                        token: token.clone(),
                        denom,
                        position,
                        epoch: None,
                    },
                );
            }
        }
        Ok(())
    }

    /// Query the ledger for the decoding of the given asset type and cache it
    /// if it is found.
    #[allow(async_fn_in_trait)]
    async fn decode_asset_type<C: Client + Sync>(
        &mut self,
        client: &C,
        asset_type: AssetType,
    ) -> Option<AssetData> {
        // Try to find the decoding in the cache
        if let decoded @ Some(_) = self.asset_types.get(&asset_type) {
            tracing::debug!(
                "Asset type: {}, found cached data: {:#?}",
                asset_type,
                decoded
            );
            return decoded.cloned();
        }
        // Query for the conversion for the given asset type
        let ConversionData {
            token,
            denomination: denom,
            digit_pos: position,
            epoch: ep,
            ..
        } = Self::get_conversion(client, asset_type, &mut self.conversions)
            .await?;
        let pre_asset_type = AssetData {
            token,
            denom,
            position,
            epoch: Some(ep),
        };
        self.asset_types.insert(asset_type, pre_asset_type.clone());
        Some(pre_asset_type)
    }

    /// Query the ledger for the conversion that is allowed for the given asset
    /// type and cache it. The target epoch must be greater than or equal to the
    /// asset's epoch. If the target epoch is None, then convert to the latest
    /// epoch.
    #[allow(async_fn_in_trait)]
    async fn query_allowed_conversion<'a, C: Client + Sync>(
        &'a mut self,
        client: &C,
        asset_type: AssetType,
        conversions: &'a mut Conversions,
    ) -> Result<(), eyre::Error> {
        let btree_map::Entry::Vacant(conv_entry) =
            conversions.entry(asset_type)
        else {
            return Ok(());
        };
        // Get the conversion for the given asset type, otherwise fail
        let Some(ConversionData {
            token,
            denomination: denom,
            digit_pos: position,
            epoch: ep,
            conversion: conv,
            merkle_path: path,
        }) = Self::get_conversion(client, asset_type, &mut self.conversions)
            .await
        else {
            return Ok(());
        };
        let asset_data = AssetData {
            token,
            denom,
            position,
            epoch: Some(ep),
        };
        self.asset_types.insert(asset_type, asset_data.clone());
        // If the conversion is 0, then we just have a pure decoding
        if !conv.is_zero() {
            conv_entry.insert((conv.into(), path));
        }
        Ok(())
    }

    /// Convert the given amount into the latest asset types whilst making a
    /// note of the conversions that were used. Note that this function does
    /// not assume that allowed conversions from the ledger are expressed in
    /// terms of the latest asset types.
    #[allow(async_fn_in_trait)]
    async fn compute_exchanged_amount(
        &mut self,
        client: &(impl Client + Sync),
        io: &impl Io,
        mut input: I128Sum,
        conversions: &mut Conversions,
    ) -> Result<(I128Sum, I128Sum), eyre::Error> {
        // Where we will track the conversion usages
        let mut usage = I128Sum::zero();
        // Where we will store our exchanged value
        let mut output = I128Sum::zero();
        // Repeatedly exchange assets until it is no longer possible
        while let Some(asset_type) = input.asset_types().next().cloned() {
            self.query_allowed_conversion(client, asset_type, conversions)
                .await?;
            // Consolidate the current amount with any dust from output.
            // Whatever is not used is moved back to output anyway.
            let dust = output.project(asset_type);
            input += dust.clone();
            output -= dust;
            // Now attempt to apply conversions
            if let Some((conv, _wit)) = conversions.get_mut(&asset_type) {
                display_line!(
                    io,
                    "converting current asset type to latest asset type..."
                );
                // Not at the target asset type, not at the latest asset type.
                // Apply conversion to get from current asset type to the latest
                // asset type.
                self.apply_conversion(
                    io,
                    conv.clone(),
                    asset_type,
                    input[&asset_type],
                    &mut usage,
                    &mut input,
                    &mut output,
                )
                .await?;
            } else {
                // At the target asset type. Then move component over to output.
                let comp = input.project(asset_type);
                output += comp.clone();
                input -= comp;
            }
        }
        Ok((output, usage))
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context and express that value in terms of the currently timestamped
    /// asset types. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    #[allow(async_fn_in_trait)]
    async fn compute_exchanged_balance(
        &mut self,
        client: &(impl Client + Sync),
        io: &impl Io,
        vk: &ViewingKey,
    ) -> Result<Option<I128Sum>, eyre::Error> {
        // First get the unexchanged balance
        if let Some(balance) = self.compute_shielded_balance(vk).await? {
            let exchanged_amount = self
                .compute_exchanged_amount(
                    client,
                    io,
                    balance,
                    &mut Conversions::new(),
                )
                .await?
                .0;
            // And then exchange balance into current asset types
            Ok(Some(exchanged_amount))
        } else {
            Ok(None)
        }
    }

    /// We estimate the next epoch rewards accumulated by the assets included in
    /// the provided raw balance, i.e. a balance based only on the available
    /// notes, without accounting for any conversions. The estimation is done by
    /// assuming the same rewards rate on each asset as in the latest masp
    /// epoch.
    #[allow(async_fn_in_trait)]
    async fn estimate_next_epoch_rewards(
        &mut self,
        context: &impl NamadaIo,
        raw_balance: &I128Sum,
    ) -> Result<DenominatedAmount, eyre::Error> {
        let native_token = Self::query_native_token(context.client()).await?;
        let native_token_denom =
            Self::query_denom(context.client(), &native_token)
                .await
                .ok_or_else(|| {
                    eyre!(
                        "Could not retrieve the denomination of the native \
                         token"
                    )
                })?;
        let epoch_zero = MaspEpoch::zero();
        let current_epoch = Self::query_masp_epoch(context.client()).await?;
        let previous_epoch = match current_epoch.prev() {
            Some(prev) => prev,
            // We are currently at MaspEpoch(0) and there are no conversions yet
            // at this point
            None => return Ok(DenominatedAmount::native(Amount::zero())),
        };
        let next_epoch = current_epoch
            .next()
            .ok_or_else(|| eyre!("The final MASP epoch is already afoot."))?;
        // Get the current amount, this serves as the reference point to
        // estimate future rewards
        let current_exchanged_balance = self
            .compute_exchanged_amount(
                context.client(),
                context.io(),
                raw_balance.to_owned(),
                &mut Conversions::new(),
            )
            .await?
            .0;

        let mut latest_conversions = Conversions::new();

        // We need to query conversions for the latest assets in the current
        // exchanged balance. For these assets there are no conversions yet so
        // we need to see if there are conversions for the previous epoch
        for (asset_type, _) in current_exchanged_balance.components() {
            let asset = match self
                .decode_asset_type(context.client(), *asset_type)
                .await
            {
                Some(
                    data @ AssetData {
                        epoch: Some(ep), ..
                    },
                ) if ep == current_epoch => data,
                _ => continue,
            };
            let redated_asset_type = asset.redate(previous_epoch).encode()?;

            self.query_allowed_conversion(
                context.client(),
                redated_asset_type,
                &mut latest_conversions,
            )
            .await?;
        }

        let mut estimated_next_epoch_conversions = Conversions::new();
        // re-date the all the latest conversions up one epoch
        for (asset_type, (conv, wit)) in latest_conversions {
            let asset = self
                .decode_asset_type(context.client(), asset_type)
                .await
                .ok_or_else(|| {
                    eyre!(
                        "Could not decode conversion asset type {}",
                        asset_type
                    )
                })?;
            let decoded_conv = self
                .decode_sum(context.client(), conv.clone().into())
                .await
                .0;
            let mut est_conv = I128Sum::zero();
            for ((_, mut asset_data), val) in decoded_conv.into_components() {
                // We must upconvert the components of the conversion if
                // this conversion is for the native token or the component
                // itself is not the native token. If instead the conversion
                // component is the native token and it is for a non-native
                // token, then we should avoid upconverting it
                // since conversions for non-native tokens must
                // always refer to a specific epoch (MaspEpoch(0)) native token
                if asset.token == native_token
                    || asset_data.token != native_token
                {
                    asset_data = asset_data.redate_to_next_epoch();
                }

                est_conv += ValueSum::from_pair(asset_data.encode()?, val)
            }
            estimated_next_epoch_conversions.insert(
                asset.redate_to_next_epoch().encode().unwrap(),
                (AllowedConversion::from(est_conv), wit.clone()),
            );
        }

        // Get the estimated future balance based on the new conversions
        let next_exchanged_balance = self
            .compute_exchanged_amount(
                context.client(),
                context.io(),
                current_exchanged_balance.clone(),
                &mut estimated_next_epoch_conversions,
            )
            .await?
            .0;

        // Extract only the native token balance for rewards. Depending on
        // rewards being enabled for the native token or not, we'll find the
        // balance we look for at either epoch 0 or the current epoch. If
        // rewards are not enabled for the native token we might have
        // balances at any epochs in between these two. These would be
        // guaranteed to be the same in both the exchanged amounts we've
        // computed here above. This means they are irrelevant for the
        // estimation of the next epoch rewards since they would cancel out
        // anyway
        let mut current_native_balance = ValueSum::<AssetType, i128>::zero();
        let mut next_native_balance = ValueSum::<AssetType, i128>::zero();
        for epoch in [epoch_zero, current_epoch, next_epoch] {
            for position in MaspDigitPos::iter() {
                let native_asset_epoch0 = AssetData {
                    token: native_token.clone(),
                    denom: native_token_denom,
                    position,
                    epoch: Some(epoch_zero),
                };
                let native_asset_epoch0_type = native_asset_epoch0
                    .encode()
                    .map_err(|_| eyre!("unable to create asset type"))?;
                let native_asset = AssetData {
                    token: native_token.clone(),
                    denom: native_token_denom,
                    position,
                    epoch: Some(epoch),
                };
                let native_asset_type = native_asset
                    .encode()
                    .map_err(|_| eyre!("unable to create asset type"))?;

                // Pre-date all the assets to MaspEpoch(0) for comparison
                if let Some((_, amt)) = current_exchanged_balance
                    .project(native_asset_type)
                    .into_components()
                    .next_back()
                {
                    current_native_balance +=
                        ValueSum::from_pair(native_asset_epoch0_type, amt);
                }
                if let Some((_, amt)) = next_exchanged_balance
                    .project(native_asset_type)
                    .into_components()
                    .next_back()
                {
                    next_native_balance +=
                        ValueSum::from_pair(native_asset_epoch0_type, amt);
                }
            }
        }

        let rewards = next_native_balance - current_native_balance;
        let decoded_rewards =
            self.decode_sum(context.client(), rewards).await.0;

        decoded_rewards
            .into_components()
            .try_fold(
                Amount::zero(),
                |acc,

                 (
                    (
                        _,
                        AssetData {
                            token,
                            denom: _,
                            position,
                            epoch,
                        },
                    ),
                    amt,
                )| {
                    // Sanity checks, the rewards must be given in the native
                    // asset at masp epoch 0
                    if token != native_token {
                        return Err(eyre!(
                            "Found reward asset other than the native token"
                        ));
                    }
                    match epoch {
                        Some(ep) if ep == epoch_zero => (),
                        _ => {
                            return Err(eyre!(
                                "Found reward asset with an epoch different \
                                 than the 0th"
                            ));
                        }
                    }

                    let amt = Amount::from_masp_denominated_i128(amt, position)
                        .ok_or_else(|| {
                            eyre!("Could not convert MASP reward to amount")
                        })?;
                    checked!(acc + amt)
                        .wrap_err("Overflow in MASP reward computation")
                },
            )
            .map(DenominatedAmount::native)
    }

    /// Select an exchanged note to bring the transaction inputs closer to the
    /// target. Essentially choose the first note that takes the accumulator
    /// closesr to the target.
    #[allow(clippy::type_complexity)]
    fn select_note_naive(
        exchanged_notes: &BTreeMap<
            NotePosition,
            (
                Note,
                I128Sum,
                I128Sum,
                ValueSum<(MaspDigitPos, Address), i128>,
            ),
        >,
        namada_acc: &ValueSum<(MaspDigitPos, Address), i128>,
        target: ValueSum<(MaspDigitPos, Address), i128>,
    ) -> Option<NotePosition> {
        // How much do we still need in order to arrive at target?
        let gap = ValueSum::zero().sup(&(target - namada_acc));

        // Iterate through the notes tracking the current best
        for (idx, (_note, _usages, _contr, namada_contr)) in exchanged_notes {
            // Find the intersection between this note's contribution and what
            // what remains for hitting the target
            let intersect = namada_contr.inf(&gap);
            // Select this exchanged note if it moves us closer to the target by
            // any amount
            if intersect > ValueSum::zero() {
                return Some(*idx);
            }
        }
        None
    }

    /// Select an exchanged note to bring the transaction inputs closer to the
    /// target. Essentially choose the note that takes the accumulator closest
    /// to the target.
    #[allow(clippy::type_complexity)]
    fn select_note_greedy(
        exchanged_notes: &BTreeMap<
            NotePosition,
            (
                Note,
                I128Sum,
                I128Sum,
                ValueSum<(MaspDigitPos, Address), i128>,
            ),
        >,
        namada_acc: &ValueSum<(MaspDigitPos, Address), i128>,
        target: ValueSum<(MaspDigitPos, Address), i128>,
    ) -> Option<NotePosition> {
        let mut max_coverage = I256::zero();
        let mut min_projection =
            ValueSum::<(MaspDigitPos, Address), i128>::zero();
        let mut note_idx = None;
        let precision = I256::from(u64::MAX);
        // How much do we still need in order to arrive at target?
        let gap = ValueSum::zero().sup(&(target.clone() - namada_acc));

        // Iterate through the notes tracking the current best
        for (idx, (_note, _usages, _contr, namada_contr)) in exchanged_notes {
            // Find the intersection between this note's contribution and what
            // what remains for hitting the target
            let intersect = namada_contr.inf(&gap);
            // The fraction of the target does this note covers
            let mut coverage = I256::zero();
            // The note measured along the components in the target
            let mut projection = ValueSum::zero();
            // Minimizing the number of notes used in a a multi-currency setting
            // involves deciding whether to take one asset or another. To
            // facilitate comparing quantities of different assets
            // with different denominations, normalize them into
            // fractions of the target amount and sum them up.
            for (asset_type, target_value) in target.components() {
                // Compute the amount this note covers using double negation
                // to round up the results
                let normalized_intersect = checked!(
                    -((I256::from(intersect.get(asset_type)) * -precision)
                        / I256::from(*target_value))
                )
                .unwrap_or(I256::maximum());
                // Accumulate the normalized contribution
                coverage = checked!(coverage + normalized_intersect)
                    .unwrap_or(I256::maximum());
                // Finally accumulate this component of the exchanged note
                projection += namada_contr.project(asset_type.clone());
            }
            // Use this exchanged note if it takes us closer to the target than
            // the others. Also use this exchanged note if there are multiple
            // notes that take us equally close to the target, and this is the
            // smallest one of the lot (when comparison is possible). The idea
            // in this case is to minimize the fragmentation of bigger notes.
            if coverage > max_coverage
                || (coverage.is_positive()
                    && coverage == max_coverage
                    && projection < min_projection)
            {
                max_coverage = coverage;
                min_projection = projection;
                note_idx = Some(*idx);
            }
        }
        note_idx
    }

    /// Collect all unspent notes for the given key and apply all possible
    /// conversions to them.
    #[allow(async_fn_in_trait)]
    async fn exchange_notes(
        &mut self,
        context: &impl NamadaIo,
        spent_notes: &mut SpentNotesTracker,
        vk: &ViewingKey,
        conversions: &mut Conversions,
    ) -> Result<
        BTreeMap<
            NotePosition,
            (
                Note,
                I128Sum,
                I128Sum,
                ValueSum<(MaspDigitPos, Address), i128>,
            ),
        >,
        eyre::Error,
    > {
        let mut exchanged_notes = BTreeMap::new();
        // Retrieve the notes that can be spent by this key
        let Some(avail_notes) = self.pos_map.get(vk).cloned() else {
            return Ok(exchanged_notes);
        };
        // Collect the notes that could potentially be used in the transaction
        for note_idx in &avail_notes {
            // Spent notes from the shielded context (i.e. from previous
            // transactions) cannot contribute a new transaction's pool.
            // Also skip spend notes already used in this transaction
            if spent_notes
                .get(vk)
                .is_some_and(|set| set.contains(note_idx))
                || self.spents.contains(note_idx)
            {
                continue;
            }
            // Get note, merkle path, diversifier associated with this ID
            let note = *self
                .note_map
                .get(note_idx)
                .ok_or_else(|| eyre!("Unable to get note {note_idx}"))?;

            // The amount contributed by this note before conversion
            let pre_contr =
                I128Sum::from_pair(note.asset_type, i128::from(note.value));
            let (contr, usages) = self
                .compute_exchanged_amount(
                    context.client(),
                    context.io(),
                    pre_contr,
                    conversions,
                )
                .await?;

            // Decode the assets in delta; any undecodable assets
            // will end up in `_rem_delta`
            let (decoded_delta, _rem_delta) =
                self.decode_sum(context.client(), contr.clone()).await;

            // Convert the delta into Namada amounts
            let converted_delta = decoded_delta.components().fold(
                ValueSum::zero(),
                |accum, ((_, asset_data), value)| {
                    accum
                        + ValueSum::from_pair(
                            (asset_data.position, asset_data.token.clone()),
                            *value,
                        )
                },
            );
            // Store additional information about the current note
            exchanged_notes
                .insert(*note_idx, (note, usages, contr, converted_delta));
        }
        Ok(exchanged_notes)
    }

    /// Collect enough relevant unspent notes in this context to exceed the
    /// given amount of the specified asset type. Return the total value
    /// accumulated plus notes and the corresponding diversifiers/merkle paths
    /// that were used to achieve the total value. Updates the changes map.
    #[allow(clippy::too_many_arguments)]
    #[allow(async_fn_in_trait)]
    async fn collect_unspent_notes(
        &mut self,
        context: &impl NamadaIo,
        spent_notes: &mut SpentNotesTracker,
        sk: PseudoExtendedKey,
        target: ValueSum<(MaspDigitPos, Address), i128>,
        conversions: &mut Conversions,
        usages: &mut I128Sum,
    ) -> Result<
        (I128Sum, Vec<(Diversifier, Note, MerklePath<Node>)>),
        eyre::Error,
    > {
        let vk = &sk.to_viewing_key().fvk.vk;
        let mut namada_acc = ValueSum::zero();
        let mut masp_acc = I128Sum::zero();
        let mut notes = Vec::new();

        // Collect all unspent notes and exchange them
        let mut exchanged_notes = self
            .exchange_notes(context, spent_notes, vk, conversions)
            .await?;
        // Finally choose and apply notes in order to meet the target amount
        while let Some(note_idx) = Self::select_note_greedy(
            &exchanged_notes,
            &namada_acc,
            target.clone(),
        ) {
            // No more transaction inputs are required once we have met
            // the target amount
            if namada_acc >= target {
                break;
            }

            // Be sure to record the conversions used in computing
            // accumulated value
            let (note, proposed_usages, contr, namada_contr) =
                exchanged_notes.remove(&note_idx).unwrap();
            masp_acc += contr;
            namada_acc += namada_contr;

            // Commit the conversions that were used to exchange
            *usages += proposed_usages;
            let merkle_path =
                self.tree.witness(note_idx).wrap_err_with(|| {
                    format!("Unable to get merkle path to note {note_idx}")
                })?;
            let diversifier = self
                .div_map
                .get(&note_idx)
                .ok_or_else(|| eyre!("Unable to get note {note_idx}"))?;
            // Commit this note to our transaction
            notes.push((*diversifier, note, merkle_path));
            // Append the note the list of used ones
            spent_notes
                .entry(vk.to_owned())
                .and_modify(|set| {
                    set.insert(note_idx);
                })
                .or_insert([note_idx].into_iter().collect());
        }
        Ok((masp_acc, notes))
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to. All asset types not corresponding to
    /// the given epoch are ignored.
    #[allow(async_fn_in_trait)]
    async fn decode_combine_sum_to_epoch<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: I128Sum,
        target_epoch: MaspEpoch,
    ) -> (ValueSum<Address, Change>, I128Sum) {
        let mut res = ValueSum::zero();
        let mut undecoded = ValueSum::zero();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            let decoded = self.decode_asset_type(client, *asset_type).await;
            // Only assets with the target timestamp count
            match decoded {
                Some(pre_asset_type)
                    if pre_asset_type
                        .epoch
                        .is_none_or(|epoch| epoch <= target_epoch) =>
                {
                    let decoded_change = Change::from_masp_denominated(
                        *val,
                        pre_asset_type.position,
                    )
                    .expect("expected this to fit");
                    res += ValueSum::from_pair(
                        pre_asset_type.token,
                        decoded_change,
                    );
                }
                None => {
                    undecoded += ValueSum::from_pair(*asset_type, *val);
                }
                _ => {}
            }
        }
        (res, undecoded)
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to and combine the denominations.
    #[allow(async_fn_in_trait)]
    async fn decode_combine_sum<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: I128Sum,
    ) -> (MaspAmount, I128Sum) {
        let mut res = MaspAmount::zero();
        let mut undecoded = ValueSum::zero();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            if let Some(decoded) =
                self.decode_asset_type(client, *asset_type).await
            {
                let decoded_change =
                    Change::from_masp_denominated(*val, decoded.position)
                        .expect("expected this to fit");
                res += MaspAmount::from_pair(
                    (decoded.epoch, decoded.token),
                    decoded_change,
                );
            } else {
                undecoded += ValueSum::from_pair(*asset_type, *val);
            }
        }
        (res, undecoded)
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to.
    #[allow(async_fn_in_trait)]
    async fn decode_sum<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: I128Sum,
    ) -> (ValueSum<(AssetType, AssetData), i128>, I128Sum) {
        let mut res = ValueSum::zero();
        let mut rem = ValueSum::zero();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            if let Some(decoded) =
                self.decode_asset_type(client, *asset_type).await
            {
                res += ValueSum::from_pair((*asset_type, decoded), *val);
            } else {
                rem += ValueSum::from_pair(*asset_type, *val);
            }
        }
        (res, rem)
    }

    /// Make shielded components to embed within a Transfer object. If no
    /// shielded payment address nor spending key is specified, then no
    /// shielded components are produced. Otherwise, a transaction containing
    /// nullifiers and/or note commitments are produced. Dummy transparent
    /// UTXOs are sometimes used to make transactions balanced, but it is
    /// understood that transparent account changes are effected only by the
    /// amounts and signatures specified by the containing Transfer object.
    #[allow(async_fn_in_trait)]
    async fn gen_shielded_transfer(
        &mut self,
        context: &impl NamadaIo,
        data: MaspTransferData,
        fee_data: Option<MaspFeeData>,
        expiration: Option<DateTimeUtc>,
        bparams: &mut impl BuildParams,
    ) -> Result<Option<ShieldedTransfer>, TransferErr> {
        // Determine epoch in which to submit potential shielded transaction
        let epoch = Self::query_masp_epoch(context.client())
            .await
            .map_err(|e| TransferErr::General(e.to_string()))?;
        // Try to get a seed from env var, if any.
        #[allow(unused_mut)]
        let mut rng = StdRng::from_rng(OsRng).unwrap();
        #[cfg(feature = "testing")]
        let mut rng = if let Ok(seed) = std::env::var(ENV_VAR_MASP_TEST_SEED)
            .map_err(|e| TransferErr::General(e.to_string()))
            .and_then(|seed| {
                let exp_str =
                    format!("Env var {ENV_VAR_MASP_TEST_SEED} must be a u64.");
                let parsed_seed: u64 =
                    seed.parse().map_err(|_| TransferErr::General(exp_str))?;
                Ok(parsed_seed)
            }) {
            tracing::warn!(
                "UNSAFE: Using a seed from {ENV_VAR_MASP_TEST_SEED} env var \
                 to build proofs."
            );
            StdRng::seed_from_u64(seed)
        } else {
            rng
        };

        // TODO: if the user requested the default expiration, there might be a
        // small discrepancy between the datetime we calculate here and the one
        // we set for the transaction (since we compute two different
        // DateTimeUtc::now()). This should be small enough to not cause
        // any issue, in case refactor the build process to compute a single
        // expiration at the beginning and use it both here and for the
        // transaction
        let expiration_height: u32 = match expiration {
            Some(expiration) => {
                // Try to match a DateTime expiration with a plausible
                // corresponding block height
                let last_block_height = u32::try_from(
                    Self::query_block(context.client())
                        .await
                        .map_err(|e| TransferErr::General(e.to_string()))?
                        .ok_or_else(|| {
                            TransferErr::General(
                                "No blocks have been produced yet".to_string(),
                            )
                        })?,
                )
                .map_err(|e| TransferErr::General(e.to_string()))?;
                let max_block_time =
                    Self::query_max_block_time_estimate(context.client())
                        .await
                        .map_err(|e| TransferErr::General(e.to_string()))?;

                #[allow(clippy::disallowed_methods)]
                let current_time = DateTimeUtc::now();
                let delta_time =
                    expiration.0.signed_duration_since(current_time.0);

                let delta_blocks = u32::try_from(
                    delta_time.num_seconds()
                        / i64::try_from(max_block_time.0).unwrap(),
                )
                .map_err(|e| TransferErr::General(e.to_string()))?;
                match checked!(last_block_height + delta_blocks) {
                    Ok(height) if height <= u32::MAX - 20 => height,
                    _ => {
                        return Err(TransferErr::General(
                            "The provided expiration exceeds the maximum \
                             allowed"
                                .to_string(),
                        ));
                    }
                }
            }
            None => {
                // NOTE: The masp library doesn't support optional expiration so
                // we set the max to mimic a never-expiring tx. We also need to
                // remove 20 which is going to be added back by the builder
                u32::MAX - 20
            }
        };
        let mut builder = Builder::<Network, PseudoExtendedKey>::new(
            NETWORK,
            // NOTE: this is going to add 20 more blocks to the actual
            // expiration but there's no other exposed function that we could
            // use from the masp crate to specify the expiration better
            expiration_height.into(),
        );

        let mut notes_tracker = SpentNotesTracker::new();
        {
            // Load the current shielded context given
            // the spending key we possess
            self.load_with_caching(context.client())
                .await
                .map_err(|e| TransferErr::General(e.to_string()))?;
        }

        let MaspTxCombinedData {
            source_data,
            target_data,
            mut denoms,
        } = Self::combine_data_for_masp_transfer(context, data, fee_data)
            .await?;
        if source_data.iter().all(|x| x.0.spending_key().is_none())
            && target_data.iter().all(|x| x.0.payment_address().is_none())
        {
            // No shielded components are needed when neither sources nor
            // destinations are shielded
            return Ok(None);
        };

        // Track the conversions used across spending keys
        let mut conversions = Conversions::new();
        let mut usages = I128Sum::zero();
        // Commit all the transaction inputs sans conversions
        for (source, amount) in &source_data {
            self.add_inputs(
                context,
                &mut builder,
                source,
                amount,
                epoch,
                &mut denoms,
                &mut notes_tracker,
                &mut conversions,
                &mut usages,
            )
            .await?;
        }
        // Commit the consolidated conversion notes from the summations
        for (asset_type, (conv, wit)) in conversions {
            let value = usages.get(&asset_type);
            if value.is_positive() {
                builder
                    .add_sapling_convert(
                        conv.clone(),
                        value as u64,
                        wit.clone(),
                    )
                    .map_err(|e| TransferErr::Build {
                        error: builder::Error::SaplingBuild(e),
                    })?;
            }
        }
        // Commit the transaction outputs
        for (target, amount) in target_data {
            self.add_outputs(
                context,
                &mut builder,
                &target,
                amount,
                epoch,
                &mut denoms,
            )
            .await?;
        }

        // Final safety check on the value balance to verify that the
        // transaction is balanced
        let value_balance = builder.value_balance();
        if !value_balance.is_zero() {
            let mut batch: Vec<MaspDataLogEntry> = vec![];

            for (asset_type, value) in value_balance.components() {
                let AssetData {
                    token,
                    denom,
                    position,
                    ..
                } = self
                    .decode_asset_type(context.client(), *asset_type)
                    .await
                    .expect(
                        "Every asset type in the builder must have a known \
                         pre-image",
                    );

                let denominated = DenominatedAmount::new(
                    Amount::from_masp_denominated_i128(*value, position)
                        .ok_or_else(|| {
                            TransferErr::General(
                                "Masp digit overflow".to_owned(),
                            )
                        })?,
                    denom,
                );

                if let Some(entry) =
                    batch.iter_mut().find(|entry| entry.token == token)
                {
                    checked!(entry.shortfall += denominated)
                        .map_err(|e| TransferErr::General(e.to_string()))?;
                } else {
                    batch.push(MaspDataLogEntry {
                        token,
                        shortfall: denominated,
                    });
                }
            }

            return Err(TransferErr::InsufficientFunds(batch.into()));
        }

        let builder_clone = builder.clone().map_builder(WalletMap);
        // Build and return the constructed transaction
        #[cfg(not(feature = "testing"))]
        let prover = self.utils.local_tx_prover();
        #[cfg(feature = "testing")]
        let prover = testing::MockTxProver(std::sync::Mutex::new(OsRng));
        let (masp_tx, metadata) = builder
            .build(
                &prover,
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                bparams,
            )
            .map_err(|error| TransferErr::Build { error })?;

        Ok(Some(ShieldedTransfer {
            builder: builder_clone,
            masp_tx,
            metadata,
            epoch,
        }))
    }

    /// Either get the denomination from the cache or query it
    #[allow(async_fn_in_trait)]
    async fn get_denom(
        client: &(impl Client + Sync),
        denoms: &mut HashMap<Address, Denomination>,
        token: &Address,
    ) -> Result<Denomination, TransferErr> {
        if let Some(denom) = denoms.get(token) {
            Ok(*denom)
        } else if let Some(denom) = Self::query_denom(client, token).await {
            denoms.insert(token.clone(), denom);
            Ok(denom)
        } else {
            Err(TransferErr::General(format!(
                "Could not find the denomination of token {token}"
            )))
        }
    }

    /// Group all the information for every source/token and target/token
    /// couple, and extract the denominations for all the tokens involved
    /// (expect the one involved in the fees if needed). This step is
    /// required so that we can collect the amount required for every couple
    /// and pass it to the appropriate function so that notes can be
    /// collected based on the correct amount.
    #[allow(async_fn_in_trait)]
    async fn combine_data_for_masp_transfer(
        context: &impl NamadaIo,
        data: MaspTransferData,
        fee_data: Option<MaspFeeData>,
    ) -> Result<MaspTxCombinedData, TransferErr> {
        let mut source_data =
            HashMap::<TransferSource, ValueSum<Address, Amount>>::new();
        let mut target_data =
            HashMap::<TransferTarget, ValueSum<Address, Amount>>::new();
        let mut denoms = HashMap::new();

        // If present, add the fee data to the rest of the transfer data
        if let Some(fee_data) = fee_data {
            let denom =
                Self::get_denom(context.client(), &mut denoms, &fee_data.token)
                    .await?;
            let amount = fee_data
                .amount
                .increase_precision(denom)
                .map_err(|e| TransferErr::General(e.to_string()))?
                .amount();

            let acc = source_data
                .entry(TransferSource::ExtendedKey(fee_data.source))
                .or_insert(ValueSum::zero());
            *acc = checked!(
                ValueSum::from_pair(fee_data.token.clone(), amount) + acc
            )
            .map_err(|e| TransferErr::General(e.to_string()))?;
            let acc = target_data
                .entry(TransferTarget::Address(fee_data.target))
                .or_insert(ValueSum::zero());
            *acc = checked!(
                ValueSum::from_pair(fee_data.token.clone(), amount) + acc
            )
            .map_err(|e| TransferErr::General(e.to_string()))?;
        }
        for (source, token, amount) in data.sources {
            let denom =
                Self::get_denom(context.client(), &mut denoms, &token).await?;
            let amount = amount
                .increase_precision(denom)
                .map_err(|e| TransferErr::General(e.to_string()))?
                .amount();

            let acc = source_data
                .entry(source.clone())
                .or_insert(ValueSum::zero());
            *acc = checked!(ValueSum::from_pair(token.clone(), amount) + acc)
                .map_err(|e| TransferErr::General(e.to_string()))?;
        }
        for (target, token, amount) in data.targets {
            let denom =
                Self::get_denom(context.client(), &mut denoms, &token).await?;
            let amount = amount
                .increase_precision(denom)
                .map_err(|e| TransferErr::General(e.to_string()))?
                .amount();

            let acc = target_data
                .entry(target.clone())
                .or_insert(ValueSum::zero());
            *acc = checked!(ValueSum::from_pair(token.clone(), amount) + acc)
                .map_err(|e| TransferErr::General(e.to_string()))?;
        }

        Ok(MaspTxCombinedData {
            source_data,
            target_data,
            denoms,
        })
    }

    /// Computes added_amt - required_amt taking care of denominations and asset
    /// decodings. Error out if required_amt is not less than added_amt.
    #[allow(async_fn_in_trait)]
    async fn compute_change(
        &mut self,
        client: &(impl Client + Sync),
        added_amt: I128Sum,
        mut required_amt: ValueSum<(MaspDigitPos, Address), i128>,
        denoms: &mut HashMap<Address, Denomination>,
    ) -> Result<I128Sum, TransferErr> {
        // Compute the amount of change due to the sender.
        let (decoded_amount, mut change) =
            self.decode_sum(client, added_amt.clone()).await;
        for ((asset_type, asset_data), value) in decoded_amount.components() {
            // Get current component of the required amount
            let req = required_amt
                .get(&(asset_data.position, asset_data.token.clone()));
            // Compute how much this decoded component covers of the requirement
            let covered = std::cmp::min(req, *value);
            // Record how far in excess of the requirement we are. This is
            // change.
            change += ValueSum::from_pair(*asset_type, value - covered);
            // Denominate the cover and decrease the required amount accordingly
            required_amt -= ValueSum::from_pair(
                (asset_data.position, asset_data.token.clone()),
                covered,
            );
        }
        // Error out if the required amount was not covered by the added amount
        if !required_amt.is_zero() {
            let mut batch: Vec<MaspDataLogEntry> = vec![];

            for ((position, token), value) in required_amt.components() {
                let denom = Self::get_denom(client, denoms, token).await?;

                let denominated = DenominatedAmount::new(
                    Amount::from_masp_denominated_i128(*value, *position)
                        .ok_or_else(|| {
                            TransferErr::General(
                                "Masp digit overflow".to_owned(),
                            )
                        })?,
                    denom,
                );

                if let Some(entry) =
                    batch.iter_mut().find(|entry| entry.token == *token)
                {
                    checked!(entry.shortfall += denominated)
                        .map_err(|e| TransferErr::General(e.to_string()))?;
                } else {
                    batch.push(MaspDataLogEntry {
                        token: token.clone(),
                        shortfall: denominated,
                    });
                }
            }

            return Err(TransferErr::InsufficientFunds(batch.into()));
        }
        Ok(change)
    }

    /// Add the necessary transaction inputs to the builder. The supplied epoch
    /// must be the current epoch.
    #[allow(async_fn_in_trait)]
    #[allow(clippy::too_many_arguments)]
    async fn add_inputs(
        &mut self,
        context: &impl NamadaIo,
        builder: &mut Builder<Network, PseudoExtendedKey>,
        source: &TransferSource,
        amount: &ValueSum<Address, Amount>,
        epoch: MaspEpoch,
        denoms: &mut HashMap<Address, Denomination>,
        notes_tracker: &mut SpentNotesTracker,
        conversions: &mut Conversions,
        usages: &mut I128Sum,
    ) -> Result<Option<I128Sum>, TransferErr> {
        // We want to fund our transaction solely from supplied spending key
        let spending_key = source.spending_key();

        // Now we build up the transaction within this object

        // Compute transparent output asset types in case they are required and
        // save them to facilitate decodings.
        let mut transparent_asset_types = BTreeMap::new();
        for token in amount.asset_types() {
            let denom = denoms.get(token).unwrap();
            for digit in MaspDigitPos::iter() {
                let mut pre_asset_type = AssetData {
                    epoch: Some(epoch),
                    token: token.clone(),
                    denom: *denom,
                    position: digit,
                };
                let asset_type = self
                    .get_asset_type(context.client(), &mut pre_asset_type)
                    .await
                    .map_err(|e| TransferErr::General(e.to_string()))?;
                transparent_asset_types.insert((token, digit), asset_type);
            }
        }
        let _ = self.save().await;

        // If there are shielded inputs
        let added_amt = if let Some(sk) = spending_key {
            // Compute the target amount to spend from the
            // input token address and namada amount. We
            // collect all words from the namada amount
            // whose values are non-zero, and pair them
            // with their corresponding masp digit position.
            let required_amt = amount.components().fold(
                ValueSum::zero(),
                |accum, (token, amount)| {
                    amount.iter_words().zip(MaspDigitPos::iter()).fold(
                        accum,
                        |accum, (value, masp_digit_pos)| {
                            if value != 0 {
                                accum
                                    + ValueSum::from_pair(
                                        (masp_digit_pos, token.clone()),
                                        i128::from(value),
                                    )
                            } else {
                                accum
                            }
                        },
                    )
                },
            );
            // Locate unspent notes that can help us meet the transaction
            // amount
            let (added_amt, unspent_notes) = self
                .collect_unspent_notes(
                    context,
                    notes_tracker,
                    sk,
                    required_amt.clone(),
                    conversions,
                    usages,
                )
                .await
                .map_err(|e| TransferErr::General(e.to_string()))?;

            // Compute the change that needs to go back to the sender
            let change = self
                .compute_change(
                    context.client(),
                    added_amt.clone(),
                    required_amt,
                    denoms,
                )
                .await?;
            // Commit the computed change back to the sender.
            for (asset_type, value) in change.components() {
                builder
                    .add_sapling_output(
                        Some(sk.to_viewing_key().fvk.ovk),
                        sk.to_viewing_key().default_address().1,
                        *asset_type,
                        *value as u64,
                        MemoBytes::empty(),
                    )
                    .map_err(|e| TransferErr::Build {
                        error: builder::Error::SaplingBuild(e),
                    })?;
            }

            // Commit the notes found to our transaction
            for (diversifier, note, merkle_path) in unspent_notes {
                builder
                    .add_sapling_spend(sk, diversifier, note, merkle_path)
                    .map_err(|e| TransferErr::Build {
                        error: builder::Error::SaplingBuild(e),
                    })?;
            }

            Some(added_amt)
        } else {
            // We add a dummy UTXO to our transaction, but only the source
            // of the parent Transfer object is used to
            // validate fund availability
            let script = source
                .t_addr_data()
                .ok_or_else(|| {
                    TransferErr::General(
                        "Source address should be transparent".into(),
                    )
                })?
                .taddress();

            for (token, amount) in amount.components() {
                for digit in MaspDigitPos::iter() {
                    let asset_type = transparent_asset_types[&(token, digit)];
                    let amount_part = digit.denominate(amount);
                    // Skip adding an input if its value is 0
                    if amount_part != 0 {
                        builder
                            .add_transparent_input(TxOut {
                                asset_type,
                                value: amount_part,
                                address: script,
                            })
                            .map_err(|e| TransferErr::Build {
                                error: builder::Error::TransparentBuild(e),
                            })?;
                    }
                }
            }

            None
        };

        Ok(added_amt)
    }

    /// Add the necessary transaction outputs to the builder
    #[allow(clippy::too_many_arguments)]
    #[allow(async_fn_in_trait)]
    async fn add_outputs(
        &mut self,
        context: &impl NamadaIo,
        builder: &mut Builder<Network, PseudoExtendedKey>,
        target: &TransferTarget,
        amount: ValueSum<Address, Amount>,
        epoch: MaspEpoch,
        denoms: &mut HashMap<Address, Denomination>,
    ) -> Result<(), TransferErr> {
        // Anotate the asset type in the value balance with its decoding in
        // order to facilitate cross-epoch computations
        let (value_balance, rem_balance) = self
            .decode_sum(context.client(), builder.value_balance())
            .await;
        assert!(
            rem_balance.is_zero(),
            "no undecodable asset types should remain at this point",
        );

        let payment_address = target.payment_address();

        for (token, amount) in amount.components() {
            // This indicates how many more assets need to be sent to the
            // receiver in order to satisfy the requested transfer
            // amount.
            let mut rem_amount = amount.raw_amount().0;

            let denom =
                Self::get_denom(context.client(), denoms, token).await?;
            // Now handle the outputs of this transaction
            // Loop through the value balance components and see which
            // ones can be given to the receiver
            for ((asset_type, decoded), val) in value_balance.components() {
                let rem_amount = &mut rem_amount[decoded.position as usize];
                // Only asset types with the correct token can contribute. But
                // there must be a demonstrated need for it.
                if decoded.token == *token
                    && decoded.denom == denom
                    && decoded
                        .epoch
                        .is_none_or(|vbal_epoch| vbal_epoch <= epoch)
                    && *rem_amount > 0
                {
                    let val = u128::try_from(*val).expect(
                        "value balance in absence of output descriptors \
                         should be non-negative",
                    );
                    // We want to take at most the remaining quota for the
                    // current denomination to the receiver
                    let contr =
                        std::cmp::min(u128::from(*rem_amount), val) as u64;
                    // Make transaction output tied to the current token,
                    // denomination, and epoch.
                    if let Some(pa) = payment_address {
                        // If there is a shielded output
                        builder
                            .add_sapling_output(
                                None,
                                pa.into(),
                                *asset_type,
                                contr,
                                MemoBytes::empty(),
                            )
                            .map_err(|e| TransferErr::Build {
                                error: builder::Error::SaplingBuild(e),
                            })?;
                    } else if let Some(t_addr_data) = target.t_addr_data() {
                        // If there is a transparent output
                        builder
                            .add_transparent_output(
                                &t_addr_data.taddress(),
                                *asset_type,
                                contr,
                            )
                            .map_err(|e| TransferErr::Build {
                                error: builder::Error::TransparentBuild(e),
                            })?;
                    } else {
                        return Result::Err(TransferErr::General(
                            "Transaction target must be a payment address or \
                             Namada address or IBC address"
                                .to_string(),
                        ));
                    }
                    // Lower what is required of the remaining contribution
                    *rem_amount -= contr;
                }
            }

            // Nothing must remain to be included in output
            if rem_amount != [0; 4] {
                return Result::Err(TransferErr::InsufficientFunds(
                    vec![MaspDataLogEntry {
                        token: token.clone(),
                        shortfall: DenominatedAmount::new(
                            namada_core::uint::Uint(rem_amount).into(),
                            denom,
                        ),
                    }]
                    .into(),
                ));
            }
        }

        Ok(())
    }

    /// Get the asset type with the given epoch, token, and denomination. If it
    /// does not exist in the protocol, then remove the timestamp. Make sure to
    /// store the derived AssetType so that future decoding is possible.
    #[allow(async_fn_in_trait)]
    async fn get_asset_type<C: Client + Sync>(
        &mut self,
        client: &C,
        decoded: &mut AssetData,
    ) -> Result<AssetType, eyre::Error> {
        let mut asset_type = decoded
            .encode()
            .map_err(|_| eyre!("unable to create asset type"))?;
        if self.decode_asset_type(client, asset_type).await.is_none() {
            // If we fail to decode the dated asset type, then remove the
            // epoch
            tracing::debug!(
                "Failed to decode dated asset type, undating it: {:#?}",
                decoded
            );
            *decoded = decoded.clone().undate();
            asset_type = decoded
                .encode()
                .map_err(|_| eyre!("unable to create asset type"))?;
            self.asset_types.insert(asset_type, decoded.clone());
        }
        Ok(asset_type)
    }

    /// Convert Namada amount and token type to MASP equivalents
    #[allow(async_fn_in_trait)]
    async fn convert_namada_amount_to_masp<C: Client + Sync>(
        &mut self,
        client: &C,
        epoch: MaspEpoch,
        token: &Address,
        denom: Denomination,
        val: Amount,
    ) -> Result<([AssetType; 4], U64Sum), eyre::Error> {
        let mut amount = U64Sum::zero();
        let mut asset_types = Vec::new();
        for position in MaspDigitPos::iter() {
            let mut pre_asset_type = AssetData {
                epoch: Some(epoch),
                token: token.clone(),
                denom,
                position,
            };
            let asset_type =
                self.get_asset_type(client, &mut pre_asset_type).await?;
            // Combine the value and unit into one amount
            amount +=
                U64Sum::from_nonnegative(asset_type, position.denominate(&val))
                    .map_err(|_| eyre!("invalid value for amount"))?;
            asset_types.push(asset_type);
        }
        Ok((
            asset_types
                .try_into()
                .expect("there must be exactly 4 denominations"),
            amount,
        ))
    }
}

impl<U: ShieldedUtils + MaybeSend + MaybeSync, T: ShieldedQueries<U>>
    ShieldedApi<U> for T
{
}

/// Check whether the given utxo memo is empty (i.e. equal to
/// [`MemoBytes::empty`]).
#[inline]
pub fn is_empty_memo(memo: &MemoBytes) -> bool {
    let memo_bytes = memo.as_array();
    memo_bytes[0] == 0xf6 && memo_bytes[1..].iter().all(|&byte| byte == 0)
}

#[cfg(test)]
mod test_shielded_wallet {
    use namada_core::address::InternalAddress;
    use namada_core::borsh::BorshSerializeExt;
    use namada_core::masp::AssetData;
    use namada_core::token::MaspDigitPos;
    use namada_io::NamadaIo;
    use proptest::proptest;
    use proptest::test_runner::Config;
    use tempfile::tempdir;

    use super::*;
    use crate::masp::fs::FsShieldedUtils;
    use crate::masp::test_utils::{
        MockNamadaIo, TestingContext, arbitrary_pa, arbitrary_vk, create_note,
    };

    #[tokio::test]
    async fn test_compute_shielded_balance() {
        let (_client_channel, context) = MockNamadaIo::new();
        let temp_dir = tempdir().unwrap();
        let mut wallet = TestingContext::new(FsShieldedUtils::new(
            temp_dir.path().to_path_buf(),
        ));
        let native_token =
            TestingContext::<FsShieldedUtils>::query_native_token(
                context.client(),
            )
            .await
            .expect("Test failed");

        let vk = arbitrary_vk();
        let pa = arbitrary_pa();
        let mut asset_data = AssetData {
            token: native_token.clone(),
            denom: 0.into(),
            position: MaspDigitPos::Zero,
            epoch: None,
        };
        // check that if no notes are found, None is returned
        let balance = wallet
            .compute_shielded_balance(&vk)
            .await
            .expect("Test failed");
        assert!(balance.is_none());

        // check that the correct balance if found for a single note
        wallet.add_note(create_note(asset_data.clone(), 10, pa), vk);
        let balance = wallet
            .compute_shielded_balance(&vk)
            .await
            .expect("Test failed")
            .expect("Test failed");
        let expected =
            I128Sum::from_nonnegative(asset_data.encode().unwrap(), 10)
                .expect("Test failed");
        assert_eq!(balance, expected);

        // check that multiple notes of the same asset are added together
        let new_note = create_note(asset_data.clone(), 11, pa);
        wallet.add_note(new_note, vk);

        let balance = wallet
            .compute_shielded_balance(&vk)
            .await
            .expect("Test failed")
            .expect("Test failed");
        let expected =
            I128Sum::from_nonnegative(asset_data.encode().unwrap(), 21)
                .expect("Test failed");
        assert_eq!(balance, expected);

        // check that spending a note works correctly
        wallet.spend_note(&new_note);

        let balance = wallet
            .compute_shielded_balance(&vk)
            .await
            .expect("Test failed")
            .expect("Test failed");
        let expected =
            I128Sum::from_nonnegative(asset_data.encode().unwrap(), 10)
                .expect("Test failed");

        assert_eq!(balance, expected);

        // check that the balance does not add together non-fungible asset types
        asset_data.epoch = Some(MaspEpoch::new(1));
        wallet.add_note(create_note(asset_data.clone(), 7, pa), vk);
        let balance = wallet
            .compute_shielded_balance(&vk)
            .await
            .expect("Test failed")
            .expect("Test failed");
        let expected = expected
            + I128Sum::from_nonnegative(asset_data.encode().unwrap(), 7)
                .expect("Test failed");

        assert_eq!(balance, expected);
        assert_eq!(balance.components().count(), 2);

        // check that a missing index causes an error
        wallet.note_map.clear();
        assert!(wallet.compute_shielded_balance(&vk).await.is_err())
    }

    // Test that `compute_exchanged_amount` can perform conversions correctly
    #[tokio::test]
    async fn test_compute_exchanged_amount() {
        let (channel, mut context) = MockNamadaIo::new();
        // the response to the current masp epoch query
        channel
            .send(MaspEpoch::new(1).serialize_to_vec())
            .expect("Test failed");
        let temp_dir = tempdir().unwrap();
        let mut wallet = TestingContext::new(FsShieldedUtils::new(
            temp_dir.path().to_path_buf(),
        ));
        let native_token =
            TestingContext::<FsShieldedUtils>::query_native_token(
                context.client(),
            )
            .await
            .expect("Test failed");
        let native_token_denom =
            TestingContext::<FsShieldedUtils>::query_denom(
                context.client(),
                &native_token,
            )
            .await
            .expect("Test failed");

        for epoch in 0..=5 {
            wallet.add_asset_type(AssetData {
                token: native_token.clone(),
                denom: native_token_denom,
                position: MaspDigitPos::Zero,
                epoch: Some(MaspEpoch::new(epoch)),
            });
        }

        for epoch in 0..5 {
            let mut conv = I128Sum::from_pair(
                AssetData {
                    token: native_token.clone(),
                    denom: native_token_denom,
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(epoch)),
                }
                .encode()
                .unwrap(),
                -2i128.pow(epoch as u32),
            );
            conv += I128Sum::from_pair(
                AssetData {
                    token: native_token.clone(),
                    denom: native_token_denom,
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(5)),
                }
                .encode()
                .unwrap(),
                2i128.pow(5),
            );
            context.add_conversions(
                AssetData {
                    token: native_token.clone(),
                    denom: native_token_denom,
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(epoch)),
                },
                (
                    native_token.clone(),
                    native_token_denom,
                    MaspDigitPos::Zero,
                    MaspEpoch::new(epoch),
                    conv,
                    MerklePath::from_path(vec![], 0),
                ),
            );
        }

        let vk = arbitrary_vk();
        let pa = arbitrary_pa();
        // Shield at epoch 1
        let asset_data = AssetData {
            token: native_token.clone(),
            denom: native_token_denom,
            position: MaspDigitPos::Zero,
            epoch: Some(MaspEpoch::new(1)),
        };
        wallet.add_asset_type(asset_data.clone());
        wallet.add_note(create_note(asset_data.clone(), 10, pa), vk);
        let balance = wallet
            .compute_shielded_balance(&vk)
            .await
            .unwrap()
            .unwrap_or_else(ValueSum::zero);

        // Query the balance with conversions at epoch 5
        let amount = wallet
            .compute_exchanged_amount(
                context.client(),
                context.io(),
                balance,
                &mut Conversions::new(),
            )
            .await
            .unwrap()
            .0;
        assert_eq!(
            amount,
            I128Sum::from_pair(
                AssetData {
                    token: native_token.clone(),
                    denom: native_token_denom,
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(5)),
                }
                .encode()
                .unwrap(),
                160,
            )
        );
    }

    #[tokio::test]
    // Test that the estimated rewards are 0 when no conversions are available
    async fn test_estimate_rewards_no_conversions() {
        let (channel, context) = MockNamadaIo::new();
        // the response to the current masp epoch query
        channel
            .send(MaspEpoch::new(1).serialize_to_vec())
            .expect("Test failed");
        let temp_dir = tempdir().unwrap();
        let mut wallet = TestingContext::new(FsShieldedUtils::new(
            temp_dir.path().to_path_buf(),
        ));

        let native_token =
            TestingContext::<FsShieldedUtils>::query_native_token(
                context.client(),
            )
            .await
            .expect("Test failed");

        let vk = arbitrary_vk();
        let pa = arbitrary_pa();
        let asset_data = AssetData {
            token: native_token.clone(),
            denom: 0.into(),
            position: MaspDigitPos::Zero,
            epoch: Some(MaspEpoch::new(1)),
        };
        wallet.add_asset_type(asset_data.clone());
        wallet.add_note(create_note(asset_data.clone(), 10, pa), vk);
        let balance = wallet
            .compute_shielded_balance(&vk)
            .await
            .unwrap()
            .unwrap_or_else(ValueSum::zero);
        let rewards_est = wallet
            .estimate_next_epoch_rewards(&context, &balance)
            .await
            .expect("Test failed");
        assert_eq!(rewards_est, DenominatedAmount::native(0.into()));
    }

    #[tokio::test]
    // Test that the estimated rewards are 0 when no conversions are available
    // to the current epoch
    async fn test_estimate_rewards_no_conversions_last_epoch() {
        let (channel, mut context) = MockNamadaIo::new();
        // the response to the current masp epoch query
        channel
            .send(MaspEpoch::new(2).serialize_to_vec())
            .expect("Test failed");
        let temp_dir = tempdir().unwrap();
        let mut wallet = TestingContext::new(FsShieldedUtils::new(
            temp_dir.path().to_path_buf(),
        ));

        let native_token =
            TestingContext::<FsShieldedUtils>::query_native_token(
                context.client(),
            )
            .await
            .expect("Test failed");
        let native_token_denom =
            TestingContext::<FsShieldedUtils>::query_denom(
                context.client(),
                &native_token,
            )
            .await
            .expect("Test failed");

        // add an old conversion for the incentivized tokens
        let mut conv = I128Sum::from_pair(
            AssetData {
                token: native_token.clone(),
                denom: native_token_denom,
                position: MaspDigitPos::Zero,
                epoch: Some(MaspEpoch::new(0)),
            }
            .encode()
            .unwrap(),
            -1,
        );
        conv += I128Sum::from_pair(
            AssetData {
                token: native_token.clone(),
                denom: native_token_denom,
                position: MaspDigitPos::Zero,
                epoch: Some(MaspEpoch::new(1)),
            }
            .encode()
            .unwrap(),
            1,
        );
        context.add_conversions(
            AssetData {
                token: native_token.clone(),
                denom: native_token_denom,
                position: MaspDigitPos::Zero,
                epoch: Some(MaspEpoch::new(0)),
            },
            (
                native_token.clone(),
                native_token_denom,
                MaspDigitPos::Zero,
                MaspEpoch::new(0),
                conv,
                MerklePath::from_path(vec![], 0),
            ),
        );

        let vk = arbitrary_vk();
        let pa = arbitrary_pa();
        let asset_data = AssetData {
            token: native_token.clone(),
            denom: native_token_denom,
            position: MaspDigitPos::Zero,
            epoch: Some(MaspEpoch::new(2)),
        };
        wallet.add_asset_type(asset_data.clone());
        wallet.add_note(create_note(asset_data.clone(), 10, pa), vk);
        let balance = wallet
            .compute_shielded_balance(&vk)
            .await
            .unwrap()
            .unwrap_or_else(ValueSum::zero);
        let rewards_est = wallet
            .estimate_next_epoch_rewards(&context, &balance)
            .await
            .expect("Test failed");
        assert_eq!(rewards_est, DenominatedAmount::native(0.into()));
    }

    proptest! {
        #![proptest_config(Config {
            cases: 10,
            .. Config::default()
        })]
        /// In this test, we have a single incentivized token
        /// shielded at MaspEpoch(2), owned by the shielded wallet.
        /// The amount of owned token is the parameter `principal`.
        ///
        /// We add a conversion from MaspEpoch(1) to MaspEpoch(2)
        /// which issues `reward_rate` nam tokens for the first of our
        /// incentivized token.
        ///
        /// Optionally, the test also shields the same `principal` amount at
        /// MaspEpoch(1).
        ///
        /// We test that estimating the rewards for MaspEpoch(3)
        /// applies the same conversions as the last epoch.
        /// The asset shielded at epoch 2 does not have conversions produced yet
        /// but we still expect the reward estimation logic to use the conversion at
        /// the previous epoch and output a correct value.
        ///
        /// Furthermore, we own `rewardless` amount of a token that
        /// is not incentivized and thus should not contribute to
        /// rewards.
        #[test]
        fn test_estimate_rewards_with_conversions(
            // fairly arbitrary upper bounds, but they are large
            // and guaranteed that 2 * reward_rate * principal
            // does not exceed 64 bits
            principal in 1u64 .. 100_000,
            reward_rate in 1i128 .. 1_000,
            rewardless in 1u64 .. 100_000,
            shield_at_previous_epoch in proptest::bool::ANY
        ) {
            // #[tokio::test] doesn't work with the proptest! macro
            tokio::runtime::Runtime::new().unwrap().block_on(async {

                let (channel, mut context) = MockNamadaIo::new();
                // the response to the current masp epoch query
                channel.send(MaspEpoch::new(2).serialize_to_vec()).expect("Test failed");
                let temp_dir = tempdir().unwrap();
                let mut wallet = TestingContext::new(FsShieldedUtils::new(
                    temp_dir.path().to_path_buf(),
                ));

                let native_token =
                    TestingContext::<FsShieldedUtils>::query_native_token(
                        context.client(),
                    )
                    .await
                    .expect("Test failed");
                let native_token_denom =
                    TestingContext::<FsShieldedUtils>::query_denom(
                        context.client(),
                        &native_token
                    )
                    .await
                    .expect("Test failed");

                // we use a random addresses as our token
                let incentivized_token = Address::Internal(InternalAddress::Pgf);
                let unincentivized = Address::Internal(InternalAddress::ReplayProtection);

                // add asset type decodings
                wallet.add_asset_type(AssetData {
                    token: native_token.clone(),
                    denom: native_token_denom,
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(0)),
                });
                wallet.add_asset_type(AssetData {
                    token: unincentivized.clone(),
                    denom: 0.into(),
                    position: MaspDigitPos::Zero,
                    epoch: None,
                 });

                for epoch in 0..4 {
                    wallet.add_asset_type(AssetData {
                        token: incentivized_token.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(epoch)),
                    });
                }

                 // add conversions for the incentivized tokens
                let mut conv = I128Sum::from_pair(
                    AssetData {
                        token: incentivized_token.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(1)),
                    }.encode().unwrap(),
                    -1,
                );
                conv += I128Sum::from_pair(
                    AssetData {
                        token: incentivized_token.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(2)),
                    }.encode().unwrap(),
                    1,
                );
                conv += I128Sum::from_pair(
                    AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(0)),
                    }.encode().unwrap(),
                    reward_rate,
                );
                context.add_conversions(
                    AssetData {
                        token: incentivized_token.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(1)),
                    },
                    (
                        incentivized_token.clone(),
                        0.into(),
                        MaspDigitPos::Zero,
                        MaspEpoch::new(1),
                        conv,
                        MerklePath::from_path(vec![], 0),
                    )
                );
                let vk = arbitrary_vk();
                let pa = arbitrary_pa();
                let asset_data = AssetData {
                    token: incentivized_token.clone(),
                    denom: 0.into(),
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(2)),
                };

                wallet.add_note(
                    create_note(asset_data, principal, pa),
                    vk,
                );

                // If this flag is set we also shield at the previous MaspEpoch(1),
                // otherwise we test that the estimation logic can
                // handle rewards for assets coming only from the current epoch,
                // i.e. assets for which there are no conversions yet.
                if shield_at_previous_epoch {
                    let asset_data = AssetData {
                        token: incentivized_token.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(1)),
                    };

                    wallet.add_note(
                        create_note(asset_data, principal, pa),
                        vk,
                    );
                }

                // add an unincentivized token which should not contribute
                // to the rewards
                let asset_data = AssetData {
                    token: unincentivized.clone(),
                    denom: 0.into(),
                    position: MaspDigitPos::Zero,
                    epoch: None,
                };

                wallet.add_note(
                    create_note(asset_data, rewardless, pa),
                    vk,
                );
                let balance = wallet
                    .compute_shielded_balance(&vk)
                    .await
                    .unwrap()
                    .unwrap_or_else(ValueSum::zero);
                let rewards_est = wallet.estimate_next_epoch_rewards(&context, &balance)
                    .await.expect("Test failed");
                assert_eq!(
                    rewards_est,
                    DenominatedAmount::native(
                        Amount::from_masp_denominated_i128(
                            // The expected rewards are just principal * reward_rate
                            // but if we also shielded at the previous epoch then we
                            // expect double the rewards
                            (1 + i128::from(shield_at_previous_epoch)) * reward_rate * i128::from(principal),
                            MaspDigitPos::Zero
                        ).unwrap()
                    ));
            });
        }

        /// In this test, we have a single incentivized token
        /// shielded at MaspEpoch(2), owned by the shielded wallet.
        /// The amount of owned token is the parameter `principal`.
        ///
        /// The test sets a current MaspEpoch that comes after MaspEpoch(2).
        ///
        /// We add a conversion from MaspEpoch(1) to MaspEpoch(2)
        /// which issues `reward_rate` nam tokens for the our incentivized token.
        ///
        /// Optionally, the test also add conversions for all the masp epochs up
        /// until the current one.
        ///
        /// We test that estimating the rewards for the current masp epoch
        /// applies the same conversions as the last epoch even if the asset has
        /// been shielded far in the past. If conversions have been produced until
        /// the current epoch than we expect the rewards to be the reward rate
        /// times the amount shielded. If we only have a conversion to MaspEpoch(2)
        /// instead, we expect rewards to be 0.
        #[test]
        fn test_estimate_rewards_with_conversions_far_past(
            principal in 1u64 .. 100_000,
            reward_rate in 1i128 .. 1_000,
            current_masp_epoch in 3u64..20,
            mint_future_rewards in proptest::bool::ANY
        ) {
            // #[tokio::test] doesn't work with the proptest! macro
            tokio::runtime::Runtime::new().unwrap().block_on(async {

                let (channel, mut context) = MockNamadaIo::new();
                // the response to the current masp epoch query
                channel.send(MaspEpoch::new(current_masp_epoch).serialize_to_vec()).expect("Test failed");
                let temp_dir = tempdir().unwrap();
                let mut wallet = TestingContext::new(FsShieldedUtils::new(
                    temp_dir.path().to_path_buf(),
                ));

                let native_token =
                    TestingContext::<FsShieldedUtils>::query_native_token(
                        context.client(),
                    )
                    .await
                    .expect("Test failed");
                let native_token_denom =
                    TestingContext::<FsShieldedUtils>::query_denom(
                        context.client(),
                        &native_token
                    )
                    .await
                    .expect("Test failed");

                // we use a random addresses as our token
                let incentivized_token = Address::Internal(InternalAddress::Pgf);

                // add asset type decodings
                wallet.add_asset_type(AssetData {
                    token: native_token.clone(),
                    denom: native_token_denom,
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(0)),
                });

                for epoch in 0..=(current_masp_epoch + 1) {
                    wallet.add_asset_type(AssetData {
                        token: incentivized_token.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(epoch)),
                    });
                }

                // if future rewards are requested add them to the context
                if mint_future_rewards {
                    for epoch in 2..current_masp_epoch {
                        let mut conv = I128Sum::from_pair(
                            AssetData {
                                token: incentivized_token.clone(),
                                denom: 0.into(),
                                position: MaspDigitPos::Zero,
                                epoch: Some(MaspEpoch::new(epoch)),
                            }.encode().unwrap(),
                            -1,
                        );
                        conv += I128Sum::from_pair(
                            AssetData {
                                token: incentivized_token.clone(),
                                denom: 0.into(),
                                position: MaspDigitPos::Zero,
                                epoch: Some(MaspEpoch::new(epoch + 1)),
                            }.encode().unwrap(),
                            1,
                        );
                        conv += I128Sum::from_pair(
                            AssetData {
                                token: native_token.clone(),
                                denom: native_token_denom,
                                position: MaspDigitPos::Zero,
                                epoch: Some(MaspEpoch::new(0)),
                            }.encode().unwrap(),
                            reward_rate,
                        );
                        context.add_conversions(
                            AssetData {
                                token: incentivized_token.clone(),
                                denom: 0.into(),
                                position: MaspDigitPos::Zero,
                                epoch: Some(MaspEpoch::new(epoch)),
                            },
                            (
                                incentivized_token.clone(),
                                0.into(),
                                MaspDigitPos::Zero,
                                MaspEpoch::new(epoch),
                                conv,
                                MerklePath::from_path(vec![], 0),
                            )
                        );
                    }
                }

                let vk = arbitrary_vk();
                let pa = arbitrary_pa();
                let asset_data = AssetData {
                    token: incentivized_token.clone(),
                    denom: 0.into(),
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(2)),
                };

                wallet.add_note(
                    create_note(asset_data, principal, pa),
                    vk,
                );

                let balance = wallet
                    .compute_shielded_balance(&vk)
                    .await
                    .unwrap()
                    .unwrap_or_else(ValueSum::zero);
                let rewards_est = wallet.estimate_next_epoch_rewards(&context, &balance)
                    .await.expect("Test failed");
                assert_eq!(
                    rewards_est,
                    DenominatedAmount::native(
                        Amount::from_masp_denominated_i128(
                            // If we produced all the conversions we expect the estimated rewards to be
                            // the shielded amount times the reward rate, otherwise
                            // we expect it to be 0
                            reward_rate * i128::from(principal) * i128::from(mint_future_rewards),
                            MaspDigitPos::Zero
                        ).unwrap()
                    ));
            });
        }

        /// In this test, we have a single incentivized token, the native one,
        /// shielded at MaspEpoch(2), owned by the shielded wallet.
        /// The amount of owned token is the parameter `principal`.
        ///
        /// We add a conversion from MaspEpoch(1) to MaspEpoch(2)
        /// which issues `reward_rate` nam tokens for our incentivized token.
        ///
        /// Optionally, the test also shields the same `principal` amount at
        /// MaspEpoch(1).
        ///
        /// We test that estimating the rewards for MaspEpoch(3)
        /// applies the same conversions as the last epoch. The asset
        /// shielded at epoch 2 does not have conversions produced yet but we
        /// still expect the reward estimation logic to use the conversion at
        /// the previous epoch and output a correct value.
        ///
        /// Furthermore, we own `principal` amount of the native token that
        /// have no conversions (MaspEpoch(0)) and thus should not contribute to rewards.
        #[test]
        fn test_estimate_rewards_native_token_with_conversions(
            // fairly arbitrary upper bounds, but they are large
            // and guaranteed that 2 * reward_rate * principal
            // does not exceed 64 bits
            principal in 1u64 .. 100_000,
            reward_rate in 1i128 .. 1_000,
            shield_at_previous_epoch in proptest::bool::ANY
        ) {
            // #[tokio::test] doesn't work with the proptest! macro
            tokio::runtime::Runtime::new().unwrap().block_on(async {

                let (channel, mut context) = MockNamadaIo::new();
                // the response to the current masp epoch query
                channel.send(MaspEpoch::new(2).serialize_to_vec()).expect("Test failed");
                let temp_dir = tempdir().unwrap();
                let mut wallet = TestingContext::new(FsShieldedUtils::new(
                    temp_dir.path().to_path_buf(),
                ));

                let native_token =
                    TestingContext::<FsShieldedUtils>::query_native_token(
                        context.client(),
                    )
                    .await
                    .expect("Test failed");
                let native_token_denom =
                    TestingContext::<FsShieldedUtils>::query_denom(
                        context.client(),
                        &native_token
                    )
                    .await
                    .expect("Test failed");

                // add asset type decodings
                for epoch in 0..4 {
                    wallet.add_asset_type(AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(epoch)),
                    });
                }

                 // add conversions for the native token
                let mut conv = I128Sum::from_pair(
                    AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(1)),
                    }.encode().unwrap(),
                    -1,
                );
                conv += I128Sum::from_pair(
                    AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(2)),
                    }.encode().unwrap(),
                    1 + reward_rate,
                );
                context.add_conversions(
                    AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(1)),
                    },
                    (
                        native_token.clone(),
                        native_token_denom,
                        MaspDigitPos::Zero,
                        MaspEpoch::new(1),
                        conv,
                        MerklePath::from_path(vec![], 0),
                    )
                );
                let vk = arbitrary_vk();
                let pa = arbitrary_pa();
                for epoch in [0, 2] {
                    let asset_data = AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(epoch)),
                    };

                    wallet.add_note(
                        create_note(asset_data, principal, pa),
                        vk,
                    );
                }

                // If this flag is set we also shield at the previous MaspEpoch(1),
                // otherwise we test that the estimation logic can
                // handle rewards for assets coming only from the current epoch,
                // i.e. assets for which there are no conversions yet.
                if shield_at_previous_epoch {
                    let asset_data = AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(1)),
                    };

                    wallet.add_note(
                        create_note(asset_data, principal, pa),
                        vk,
                    );
                }

                let balance = wallet
                    .compute_shielded_balance(&vk)
                    .await
                    .unwrap()
                    .unwrap_or_else(ValueSum::zero);
                let rewards_est = wallet.estimate_next_epoch_rewards(&context, &balance).await.expect("Test failed");
                if shield_at_previous_epoch {
                    assert_eq!(
                        rewards_est,
                        DenominatedAmount::native(
                            Amount::from_masp_denominated_i128(
                                // The expected rewards are just principal * reward_rate
                                // but if we also shielded at the previous epoch then we
                                // expect double the rewards and, on top of that, we
                                // need to account for the compounding of rewards
                                // given to the native token, hence the (2 + reward_rate)
                                (2 + reward_rate) * reward_rate * i128::from(principal),
                                MaspDigitPos::Zero
                            ).unwrap()
                        )
                    );
                } else {
                    assert_eq!(
                        rewards_est,
                        DenominatedAmount::native(
                            Amount::from_masp_denominated_i128(
                                i128::from(principal) * reward_rate,
                                MaspDigitPos::Zero
                            ).unwrap()
                        )
                    );
                }
            });
        }

        /// In this test, we have a single incentivized token, the native one,
        /// shielded at MaspEpoch(2), owned by the shielded wallet.
        /// The amount of owned token is 1.
        ///
        /// The test sets a current MaspEpoch that comes after MaspEpoch(2).
        ///
        /// If requested, we add a conversion from MaspEpoch(2) to the current MaspEpoch
        /// which issue `reward_rate` nam tokens for our incentivized token.
        ///
        /// We test that estimating the rewards for the current masp epoch
        /// applies the same conversions as the last epoch even if the asset has
        /// been shielded far in the past. If conversions have been produced until
        /// the current epoch than we expect the rewards to be the reward rate
        /// times the amount shielded. If we only have a conversion to MaspEpoch(2)
        /// instead, we expect rewards to be 0.
        #[test]
        fn test_estimate_rewards_native_token_with_conversions_far_past(
            reward_rate in 1i128 .. 1_000,
            current_masp_epoch in 3u64..10,
            mint_future_rewards in proptest::bool::ANY
        ) {
            // #[tokio::test] doesn't work with the proptest! macro
            tokio::runtime::Runtime::new().unwrap().block_on(async {

                let (channel, mut context) = MockNamadaIo::new();
                // the response to the current masp epoch query
                channel.send(MaspEpoch::new(current_masp_epoch).serialize_to_vec()).expect("Test failed");
                let temp_dir = tempdir().unwrap();
                let mut wallet = TestingContext::new(FsShieldedUtils::new(
                    temp_dir.path().to_path_buf(),
                ));

                let native_token =
                    TestingContext::<FsShieldedUtils>::query_native_token(
                        context.client(),
                    )
                    .await
                    .expect("Test failed");
                let native_token_denom =
                    TestingContext::<FsShieldedUtils>::query_denom(
                        context.client(),
                        &native_token
                    )
                    .await
                    .expect("Test failed");

                // add asset type decodings
                for epoch in 0..=(current_masp_epoch + 1){
                    wallet.add_asset_type(AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(epoch)),
                    });
                }

                // if future rewards are requested add them to the context
                if mint_future_rewards {
                    for epoch in 2..current_masp_epoch {
                        let mut conv = I128Sum::from_pair(
                            AssetData {
                                token: native_token.clone(),
                                denom: native_token_denom,
                                position: MaspDigitPos::Zero,
                                epoch: Some(MaspEpoch::new(epoch)),
                            }.encode().unwrap(),
                            -1,
                        );
                        conv += I128Sum::from_pair(
                            AssetData {
                                token: native_token.clone(),
                                denom: native_token_denom,
                                position: MaspDigitPos::Zero,
                                epoch: Some(MaspEpoch::new(epoch + 1)),
                            }.encode().unwrap(),
                            1 + reward_rate,
                        );
                        context.add_conversions(
                            AssetData {
                                token: native_token.clone(),
                                denom: native_token_denom,
                                position: MaspDigitPos::Zero,
                                epoch: Some(MaspEpoch::new(epoch)),
                            },
                            (
                                native_token.clone(),
                                native_token_denom,
                                MaspDigitPos::Zero,
                                MaspEpoch::new(epoch),
                                conv,
                                MerklePath::from_path(vec![], 0),
                            )
                        );
                    }
                }

                let vk = arbitrary_vk();
                let pa = arbitrary_pa();
                let asset_data = AssetData {
                    token: native_token.clone(),
                    denom: native_token_denom,
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(2)),
                };

                wallet.add_note(
                    create_note(asset_data, 1, pa),
                    vk,
                );

                let balance = wallet
                    .compute_shielded_balance(&vk)
                    .await
                    .unwrap()
                    .unwrap_or_else(ValueSum::zero);
                let rewards_est = wallet.estimate_next_epoch_rewards(&context, &balance).await.expect("Test failed");
                let balance_at_epoch_3 = 1 + reward_rate;
                let balance_at_current_epoch = i128::pow(balance_at_epoch_3, (current_masp_epoch - 2) as u32);
                let estimated_balance_at_next_epoch = i128::pow(balance_at_epoch_3, (current_masp_epoch - 1) as u32);
                assert_eq!(
                    rewards_est,
                    DenominatedAmount::native(
                        Amount::from_masp_denominated_i128(
                            i128::from(mint_future_rewards) * (estimated_balance_at_next_epoch - balance_at_current_epoch),
                            MaspDigitPos::Zero
                        ).unwrap()
                    )
                );
            });
        }

        /// A more complicated test that checks asset estimations when multiple
        /// different incentivized assets are present and multiple conversions need
        /// to be applied to the same note.
        #[test]
        fn test_ests_with_mult_incentivized_assets(
           principal1 in 1u64..10_000,
           principal2 in 1u64..10_000,
           tok1_reward_rate in 1i128..1000,
           tok2_reward_rate in 1i128..1000,
        ) {

            // #[tokio::test] doesn't work with the proptest! macro
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (channel, mut context) = MockNamadaIo::new();
                // the response to the current masp epoch query
                channel
                    .send(MaspEpoch::new(3).serialize_to_vec())
                    .expect("Test failed");
                let temp_dir = tempdir().unwrap();
                let mut wallet = TestingContext::new(FsShieldedUtils::new(
                    temp_dir.path().to_path_buf(),
                ));

                let native_token =
                    TestingContext::<FsShieldedUtils>::query_native_token(
                        context.client(),
                    )
                    .await
                    .expect("Test failed");
                let native_token_denom =
                    TestingContext::<FsShieldedUtils>::query_denom(
                        context.client(),
                        &native_token
                    )
                    .await
                    .expect("Test failed");

                // we use a random addresses as our tokens
                let tok1 = Address::Internal(InternalAddress::Pgf);
                let tok2 = Address::Internal(InternalAddress::ReplayProtection);

                // add asset type decodings
                for epoch in 0..5 {
                    wallet.add_asset_type(AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(epoch)),
                    });
                }

                for tok in [&tok1, &tok2] {
                    for epoch in 0..5 {
                        wallet.add_asset_type(AssetData {
                            token: tok.clone(),
                            denom: 0.into(),
                            position: MaspDigitPos::Zero,
                            epoch: Some(MaspEpoch::new(epoch)),
                        });
                    }
                }

                // add empty conversions for the native token
                for epoch in 0..2 {
                    let mut conv = I128Sum::from_pair(
                        AssetData {
                            token: native_token.clone(),
                            denom: native_token_denom,
                            position: MaspDigitPos::Zero,
                            epoch: Some(MaspEpoch::new(epoch)),
                        }.encode().unwrap(),
                        -1,
                    );
                    conv += I128Sum::from_pair(
                        AssetData {
                            token: native_token.clone(),
                            denom: native_token_denom,
                            position: MaspDigitPos::Zero,
                            epoch: Some(MaspEpoch::new(epoch + 1)),
                        }.encode().unwrap(),
                        1,
                    );
                    context.add_conversions(
                        AssetData {
                            token: native_token.clone(),
                            denom: native_token_denom,
                            position: MaspDigitPos::Zero,
                            epoch: Some(MaspEpoch::new(epoch)),
                        },
                        (
                            native_token.clone(),
                            native_token_denom,
                            MaspDigitPos::Zero,
                            MaspEpoch::new(epoch),
                            conv,
                            MerklePath::from_path(vec![], 0),
                        )
                    );
                }
                // add native conversion from epoch 2 -> 3
                 let mut conv = I128Sum::from_pair(
                        AssetData {
                            token: native_token.clone(),
                            denom: native_token_denom,
                            position: MaspDigitPos::Zero,
                            epoch: Some(MaspEpoch::new(2)),
                        }.encode().unwrap(),
                        -1,
                    );
                    conv += I128Sum::from_pair(
                        AssetData {
                            token: native_token.clone(),
                            denom: native_token_denom,
                            position: MaspDigitPos::Zero,
                            epoch: Some(MaspEpoch::new(3)),
                        }.encode().unwrap(),
                        2,
                    );
                    context.add_conversions(
                        AssetData {
                            token: native_token.clone(),
                            denom: native_token_denom,
                            position: MaspDigitPos::Zero,
                            epoch: Some(MaspEpoch::new(2)),
                        },
                        (
                            native_token.clone(),
                            native_token_denom,
                            MaspDigitPos::Zero,
                            MaspEpoch::new(2),
                            conv,
                            MerklePath::from_path(vec![], 0),
                        )
                    );

                // add conversions from epoch 1 -> 2 for tok1
                let mut conv = I128Sum::from_pair(
                    AssetData {
                        token: tok1.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(1)),
                    }
                        .encode()
                        .unwrap(),
                    -1,
                );
                conv += I128Sum::from_pair(
                    AssetData {
                        token: tok1.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(2)),
                    }
                        .encode()
                        .unwrap(),
                    1,
                );
                conv += I128Sum::from_pair(
                    AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(0)),
                    }
                        .encode()
                        .unwrap(),
                    tok1_reward_rate,
                );
                context.add_conversions(
                    AssetData {
                        token: tok1.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(1)),
                    },
                    (
                        tok1.clone(),
                        0.into(),
                        MaspDigitPos::Zero,
                        MaspEpoch::new(1),
                        conv,
                        MerklePath::from_path(vec![], 0),
                    ),
                );

                // add conversions from epoch 2 -> 3 for tok1
                let mut conv = I128Sum::from_pair(
                    AssetData {
                        token: tok1.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(2)),
                    }
                        .encode()
                        .unwrap(),
                    -1,
                );
                conv += I128Sum::from_pair(
                    AssetData {
                        token: tok1.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(3)),
                    }
                        .encode()
                        .unwrap(),
                    1,
                );
                conv += I128Sum::from_pair(
                    AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(0)),
                    }
                        .encode()
                        .unwrap(),
                    1,
                );
                context.add_conversions(
                    AssetData {
                        token: tok1.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(2)),
                    },
                    (
                        tok1.clone(),
                        0.into(),
                        MaspDigitPos::Zero,
                        MaspEpoch::new(2),
                        conv,
                        MerklePath::from_path(vec![], 0),
                    ),
                );
                // add conversions from epoch 2 -> 3 for tok2
                let mut conv = I128Sum::from_pair(
                    AssetData {
                        token: tok2.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(2)),
                    }
                        .encode()
                        .unwrap(),
                    -1,
                );
                conv += I128Sum::from_pair(
                    AssetData {
                        token: tok2.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(3)),
                    }
                        .encode()
                        .unwrap(),
                    1,
                );
                conv += I128Sum::from_pair(
                    AssetData {
                        token: native_token.clone(),
                        denom: native_token_denom,
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(0)),
                    }
                        .encode()
                        .unwrap(),
                    tok2_reward_rate,
                );
                context.add_conversions(
                    AssetData {
                        token: tok2.clone(),
                        denom: 0.into(),
                        position: MaspDigitPos::Zero,
                        epoch: Some(MaspEpoch::new(2)),
                    },
                    (
                        tok2.clone(),
                        0.into(),
                        MaspDigitPos::Zero,
                        MaspEpoch::new(2),
                        conv,
                        MerklePath::from_path(vec![], 0),
                    ),
                );

                // create note with tok1
                let vk = arbitrary_vk();
                let pa = arbitrary_pa();
                let asset_data = AssetData {
                    token: tok1.clone(),
                    denom: 0.into(),
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(1)),
                };

                wallet.add_note(
                    create_note(asset_data.clone(), principal1, pa),
                    vk,
                );

                // create note with tok2
                let asset_data = AssetData {
                    token: tok2.clone(),
                    denom: 0.into(),
                    position: MaspDigitPos::Zero,
                    epoch: Some(MaspEpoch::new(2)),
                };

                wallet.add_note(
                    create_note(asset_data.clone(), principal2, pa),
                    vk,
                );

                let balance = wallet
                    .compute_shielded_balance(&vk)
                    .await
                    .unwrap()
                    .unwrap_or_else(ValueSum::zero);
                let rewards_est = wallet
                    .estimate_next_epoch_rewards(&context, &balance)
                    .await
                    .expect("Test failed");
                // The native token balances at epoch 3 and 4 are given by the shielded amounts times the rewards times the conversion for the native asset
                let native_balance_at_3 = (i128::from(principal1) * (tok1_reward_rate + 1) + i128::from(principal2) * tok2_reward_rate) * 2;
                let estimated_native_balance_at_4= (i128::from(principal1) * (tok1_reward_rate + 2) + 2 * i128::from(principal2) * tok2_reward_rate) * 4;
                assert_eq!(
                    rewards_est,
                    // The estimated rewards are just the difference between the two native token balances
                    DenominatedAmount::native(
                        Amount::from_masp_denominated_i128(
                            estimated_native_balance_at_4 - native_balance_at_3,
                             MaspDigitPos::Zero
                        ).unwrap()
                    )
                );
            });
        }
    }
}
