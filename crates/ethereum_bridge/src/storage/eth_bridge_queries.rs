//! Storage queries for ethereum bridge.

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::address::Address;
use namada_core::chain::{BlockHeight, Epoch};
use namada_core::eth_abi::Encode;
use namada_core::eth_bridge_pool::PendingTransfer;
use namada_core::ethereum_events::{
    EthAddress, EthereumEvent, GetEventNonce, TransferToEthereum, Uint,
};
use namada_core::keccak::KeccakHash;
use namada_core::storage::Key as StorageKey;
use namada_core::voting_power::{EthBridgeVotingPower, FractionalVotingPower};
use namada_core::{hints, token};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_proof_of_stake::queries::get_total_voting_power;
use namada_proof_of_stake::storage::{
    read_consensus_validator_set_addresses_with_stake, read_pos_params,
    validator_eth_cold_key_handle, validator_eth_hot_key_handle,
};
use namada_state::{DBIter, DBRead, StorageHasher, StoreType, WlState};
use namada_storage::StorageRead;
use namada_systems::governance;
use namada_vote_ext::validator_set_update::{
    EthAddrBook, ValidatorSetArgs, VotingPowersMap, VotingPowersMapExt,
};

use crate::storage::proof::BridgePoolRootProof;
use crate::storage::{active_key, bridge_pool, vote_tallies, whitelist};

/// Check if the Ethereum Bridge has been enabled at compile time.
pub const fn is_bridge_comptime_enabled() -> bool {
    cfg!(feature = "namada-eth-bridge")
}

/// Check if the bridge is disabled, enabled, or scheduled to be
/// enabled at a specified [`Epoch`].
pub fn check_bridge_status<S: StorageRead>(
    storage: &S,
) -> namada_storage::Result<EthBridgeStatus> {
    #[cfg(not(test))]
    if !is_bridge_comptime_enabled() {
        return Ok(EthBridgeStatus::Disabled);
    }
    let status = storage
        .read(&active_key())?
        .expect("The Ethereum bridge active key should be in storage");
    Ok(status)
}

/// Returns a boolean indicating whether the bridge is
/// currently active at the specified [`Epoch`].
pub fn is_bridge_active_at<S: StorageRead>(
    storage: &S,
    queried_epoch: Epoch,
) -> namada_storage::Result<bool> {
    Ok(match check_bridge_status(storage)? {
        EthBridgeStatus::Disabled => false,
        EthBridgeStatus::Enabled(EthBridgeEnabled::AtGenesis) => true,
        EthBridgeStatus::Enabled(EthBridgeEnabled::AtEpoch(enabled_epoch)) => {
            queried_epoch >= enabled_epoch
        }
    })
}

/// This enum is used as a parameter to
/// [`EthBridgeQueriesHook::must_send_valset_upd`].
pub enum SendValsetUpd {
    /// Check if it is possible to send a validator set update
    /// vote extension at the current block height.
    Now,
    /// Check if it is possible to send a validator set update
    /// vote extension at the previous block height.
    AtPrevHeight,
}

#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshDeserializer,
    BorshSerialize,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
)]
/// An enum indicating if the Ethereum bridge is enabled.
pub enum EthBridgeStatus {
    /// The bridge is disabled
    Disabled,
    /// The bridge is enabled
    Enabled(EthBridgeEnabled),
}

#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshDeserializer,
    BorshSerialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
/// Enum indicating if the bridge was initialized at genesis
/// or a later epoch.
pub enum EthBridgeEnabled {
    /// Bridge is enabled from genesis
    AtGenesis,
    /// Bridge is enabled from this epoch
    /// onwards. a validator set proof must
    /// exist for this epoch.
    AtEpoch(Epoch),
}

/// Methods used to query blockchain Ethereum bridge related state.
pub trait EthBridgeQueries {
    /// The underlying storage type.
    type Storage;

    /// Return a handle to [`EthBridgeQueries`].
    fn ethbridge_queries(&self) -> EthBridgeQueriesHook<'_, Self::Storage>;
}

impl<D, H> EthBridgeQueries for WlState<'_, D, H>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type Storage = Self;

    #[inline]
    fn ethbridge_queries(&self) -> EthBridgeQueriesHook<'_, Self> {
        EthBridgeQueriesHook { state: self }
    }
}

/// A handle to [`EthBridgeQueries`].
///
/// This type is a wrapper around a pointer to a [`WlState`].
#[derive(Debug)]
#[repr(transparent)]
pub struct EthBridgeQueriesHook<'db, S> {
    state: &'db S,
}

impl<S> Clone for EthBridgeQueriesHook<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for EthBridgeQueriesHook<'_, S> {}

impl<'db, D, H> EthBridgeQueriesHook<'db, WlState<'_, D, H>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    /// Return a handle to the inner [`WlState`].
    #[inline]
    pub fn state(self) -> &'db WlState<'db, D, H> {
        self.state
    }

    /// Check if a validator set update proof is available for
    /// the given [`Epoch`].
    pub fn valset_upd_seen(self, epoch: Epoch) -> bool {
        if hints::unlikely(epoch.0 == 0) {
            unreachable!(
                "There are no validator set update proofs for the first epoch"
            );
        }
        let valset_upd_keys = vote_tallies::Keys::from(&epoch);
        self.state
            .read(&valset_upd_keys.seen())
            .expect("Reading a value from storage should not fail")
            .unwrap_or(false)
    }

    /// Check if the bridge is disabled, enabled, or
    /// scheduled to be enabled at a specified epoch.
    #[inline]
    pub fn check_bridge_status(self) -> EthBridgeStatus {
        check_bridge_status(self.state).expect(
            "Failed to read Ethereum bridge activation status from storage",
        )
    }

    /// Returns a boolean indicating whether the bridge is
    /// currently active.
    #[inline]
    pub fn is_bridge_active(self) -> bool {
        is_bridge_active_at(
            self.state,
            self.state.in_mem().get_current_epoch().0,
        )
        .expect("Failed to read Ethereum bridge activation status from storage")
    }

    /// Behaves exactly like [`Self::is_bridge_active`], but performs
    /// the check at the given [`Epoch`].
    #[inline]
    pub fn is_bridge_active_at(self, queried_epoch: Epoch) -> bool {
        is_bridge_active_at(self.state, queried_epoch).expect(
            "Failed to read Ethereum bridge activation status from storage",
        )
    }

    /// Get the nonce of the next transfers to Namada event to be processed.
    pub fn get_next_nam_transfers_nonce(self) -> Uint {
        self.state
            .in_mem()
            .eth_events_queue
            .transfers_to_namada
            .get_event_nonce()
    }

    /// Get the latest nonce for the Ethereum bridge
    /// pool.
    pub fn get_bridge_pool_nonce(self) -> Uint {
        self.state
            .read(&bridge_pool::get_nonce_key())
            .expect("Reading Bridge pool nonce shouldn't fail.")
            .expect("Bridge pool nonce must be present.")
    }

    /// Get the nonce at a particular block height.
    pub fn get_bridge_pool_nonce_at_height(self, height: BlockHeight) -> Uint {
        Uint::try_from_slice(
            &self
                .state
                .db()
                .read_subspace_val_with_height(
                    &bridge_pool::get_nonce_key(),
                    height,
                    self.state.in_mem().get_last_block_height(),
                )
                .expect("Reading signed Bridge pool nonce shouldn't fail.")
                .expect("Reading signed Bridge pool nonce shouldn't fail."),
        )
        .expect("Deserializing the signed nonce from storage should not fail.")
    }

    /// Get the latest root of the Ethereum bridge
    /// pool Merkle tree.
    pub fn get_bridge_pool_root(self) -> KeccakHash {
        self.state
            .in_mem()
            .block
            .tree
            .sub_root(&StoreType::BridgePool)
            .into()
    }

    /// Get a quorum of validator signatures over
    /// the concatenation of the latest bridge pool
    /// root and nonce.
    ///
    /// Also returns the block height at which the
    /// Bridge pool root was originally signed.
    ///
    /// No value exists when the bridge if first
    /// started.
    pub fn get_signed_bridge_pool_root(
        self,
    ) -> Option<(BridgePoolRootProof, BlockHeight)> {
        self.state
            .read(&bridge_pool::get_signed_root_key())
            .expect("Reading signed Bridge pool root shouldn't fail.")
    }

    /// Get the root of the Ethereum bridge
    /// pool Merkle tree at a given height.
    pub fn get_bridge_pool_root_at_height(
        self,
        height: BlockHeight,
    ) -> Option<KeccakHash> {
        let base_tree = self
            .state
            .get_merkle_tree(height, Some(StoreType::BridgePool))
            .ok()?;
        Some(base_tree.sub_root(&StoreType::BridgePool).into())
    }

    /// Determines if it is possible to send a validator set update vote
    /// extension at the provided [`BlockHeight`] in [`SendValsetUpd`].
    #[inline]
    pub fn must_send_valset_upd(self, can_send: SendValsetUpd) -> bool {
        if !is_bridge_comptime_enabled() {
            // the bridge is disabled at compile time, therefore
            // we must never submit validator set updates
            false
        } else if matches!(can_send, SendValsetUpd::AtPrevHeight) {
            // when checking vote extensions in Prepare
            // and ProcessProposal, we simply return true
            true
        } else {
            // offset of 1 => are we at the 2nd
            // block within the epoch?
            self.state.is_deciding_offset_within_epoch(1)
        }
    }

    /// For a given Namada validator, return its corresponding Ethereum bridge
    /// address.
    #[inline]
    pub fn get_ethbridge_from_namada_addr<Gov>(
        self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress>
    where
        Gov: governance::Read<WlState<'db, D, H>>,
    {
        let epoch =
            epoch.unwrap_or_else(|| self.state.in_mem().get_current_epoch().0);
        let params = read_pos_params::<_, Gov>(self.state).unwrap();
        validator_eth_hot_key_handle(validator)
            .get(self.state, epoch, &params)
            .expect("Should be able to read eth hot key from storage")
            .and_then(|ref pk| pk.try_into().ok())
    }

    /// For a given Namada validator, return its corresponding Ethereum
    /// governance address.
    #[inline]
    pub fn get_ethgov_from_namada_addr<Gov>(
        self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress>
    where
        Gov: governance::Read<WlState<'db, D, H>>,
    {
        let epoch =
            epoch.unwrap_or_else(|| self.state.in_mem().get_current_epoch().0);
        let params = read_pos_params::<_, Gov>(self.state).unwrap();
        validator_eth_cold_key_handle(validator)
            .get(self.state, epoch, &params)
            .expect("Should be able to read eth cold key from storage")
            .and_then(|ref pk| pk.try_into().ok())
    }

    /// For a given Namada validator, return its corresponding Ethereum
    /// address book.
    #[inline]
    pub fn get_eth_addr_book<Gov>(
        self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddrBook>
    where
        Gov: governance::Read<WlState<'db, D, H>>,
    {
        let bridge =
            self.get_ethbridge_from_namada_addr::<Gov>(validator, epoch)?;
        let governance =
            self.get_ethgov_from_namada_addr::<Gov>(validator, epoch)?;
        Some(EthAddrBook {
            hot_key_addr: bridge,
            cold_key_addr: governance,
        })
    }

    /// Extension of [`read_consensus_validator_set_addresses_with_stake`],
    /// which additionally returns all Ethereum addresses of some validator.
    #[inline]
    pub fn get_consensus_eth_addresses<Gov>(
        self,
        epoch: Epoch,
    ) -> impl Iterator<Item = (EthAddrBook, Address, token::Amount)> + 'db
    where
        Gov: governance::Read<WlState<'db, D, H>>,
    {
        read_consensus_validator_set_addresses_with_stake(self.state, epoch)
            .unwrap()
            .into_iter()
            .map(move |validator| {
                let eth_addr_book = self
                    .state
                    .ethbridge_queries()
                    .get_eth_addr_book::<Gov>(&validator.address, Some(epoch))
                    .expect("All Namada validators should have Ethereum keys");
                (eth_addr_book, validator.address, validator.bonded_stake)
            })
    }

    /// Query a chosen [`ValidatorSetArgs`] at the given [`Epoch`].
    /// Also returns a map of each validator's voting power.
    fn get_validator_set_args<Gov, F>(
        self,
        epoch: Option<Epoch>,
        mut select_validator: F,
    ) -> (ValidatorSetArgs, VotingPowersMap)
    where
        Gov: governance::Read<WlState<'db, D, H>>,
        F: FnMut(&EthAddrBook) -> EthAddress,
    {
        let epoch =
            epoch.unwrap_or_else(|| self.state.in_mem().get_current_epoch().0);

        let voting_powers_map: VotingPowersMap = self
            .get_consensus_eth_addresses::<Gov>(epoch)
            .map(|(addr_book, _, power)| (addr_book, power))
            .collect();

        let total_power =
            get_total_voting_power::<_, Gov>(self.state, epoch).into();
        let (validators, voting_powers) = voting_powers_map
            .get_sorted()
            .into_iter()
            .map(|(addr_book, &power)| {
                let voting_power: EthBridgeVotingPower =
                    FractionalVotingPower::new(power.into(), total_power)
                        .expect("Fractional voting power should be >1")
                        .try_into()
                        .unwrap();
                (select_validator(addr_book), voting_power)
            })
            .unzip();

        (
            ValidatorSetArgs {
                epoch,
                validators,
                voting_powers,
            },
            voting_powers_map,
        )
    }

    /// Query the Bridge [`ValidatorSetArgs`] at the given [`Epoch`].
    /// Also returns a map of each validator's voting power.
    #[inline]
    pub fn get_bridge_validator_set<Gov>(
        self,
        epoch: Option<Epoch>,
    ) -> (ValidatorSetArgs, VotingPowersMap)
    where
        Gov: governance::Read<WlState<'db, D, H>>,
    {
        self.get_validator_set_args::<Gov, _>(
            epoch,
            |&EthAddrBook { hot_key_addr, .. }| hot_key_addr,
        )
    }

    /// Query the Governance [`ValidatorSetArgs`] at the given [`Epoch`].
    /// Also returns a map of each validator's voting power.
    #[inline]
    pub fn get_governance_validator_set<Gov>(
        self,
        epoch: Option<Epoch>,
    ) -> (ValidatorSetArgs, VotingPowersMap)
    where
        Gov: governance::Read<WlState<'db, D, H>>,
    {
        self.get_validator_set_args::<Gov, _>(
            epoch,
            |&EthAddrBook { cold_key_addr, .. }| cold_key_addr,
        )
    }

    /// Check if the token at the given [`EthAddress`] is whitelisted.
    pub fn is_token_whitelisted(self, &token: &EthAddress) -> bool {
        let key = whitelist::Key {
            asset: token,
            suffix: whitelist::KeyType::Whitelisted,
        }
        .into();

        self.state
            .read(&key)
            .expect("Reading from storage should not fail")
            .unwrap_or(false)
    }

    /// Fetch the token cap of the asset associated with the given
    /// [`EthAddress`].
    ///
    /// If the asset has never been whitelisted, return [`None`].
    pub fn get_token_cap(self, &token: &EthAddress) -> Option<token::Amount> {
        let key = whitelist::Key {
            asset: token,
            suffix: whitelist::KeyType::Cap,
        }
        .into();

        self.state
            .read(&key)
            .expect("Reading from storage should not fail")
    }

    /// Fetch the token supply of the asset associated with the given
    /// [`EthAddress`].
    ///
    /// If the asset has never been minted, return [`None`].
    pub fn get_token_supply(
        self,
        &token: &EthAddress,
    ) -> Option<token::Amount> {
        let key = whitelist::Key {
            asset: token,
            suffix: whitelist::KeyType::WrappedSupply,
        }
        .into();

        self.state
            .read(&key)
            .expect("Reading from storage should not fail")
    }

    /// Return the number of ERC20 and NUT assets to be minted,
    /// after receiving a "transfer to Namada" Ethereum event.
    ///
    /// NUTs are minted when:
    ///
    /// 1. `token` is not whitelisted.
    /// 2. `token` has exceeded the configured token caps, after minting
    ///    `amount_to_mint`.
    pub fn get_eth_assets_to_mint(
        self,
        token: &EthAddress,
        amount_to_mint: token::Amount,
    ) -> EthAssetMint {
        if !self.is_token_whitelisted(token) {
            return EthAssetMint {
                nut_amount: amount_to_mint,
                erc20_amount: token::Amount::zero(),
            };
        }

        let supply = self.get_token_supply(token).unwrap_or_default();
        let cap = self.get_token_cap(token).unwrap_or_default();

        if hints::unlikely(cap < supply) {
            panic!(
                "Namada's state is faulty! The Ethereum ERC20 asset {token} \
                 has a higher minted supply than the configured token cap: \
                 cap:{cap:?} < supply:{supply:?}"
            );
        }

        if amount_to_mint
            .checked_add(supply)
            .expect("Token amount shouldn't overflow")
            > cap
        {
            let erc20_amount =
                cap.checked_sub(supply).expect("Cannot underflow");
            let nut_amount = amount_to_mint
                .checked_sub(erc20_amount)
                .expect("Cannot underflow");

            return EthAssetMint {
                nut_amount,
                erc20_amount,
            };
        }

        EthAssetMint {
            erc20_amount: amount_to_mint,
            nut_amount: token::Amount::zero(),
        }
    }

    /// Given a [`TransferToEthereum`] event, look-up the corresponding
    /// [`PendingTransfer`].
    pub fn lookup_transfer_to_eth(
        self,
        transfer: &TransferToEthereum,
    ) -> Option<(PendingTransfer, StorageKey)> {
        let pending_key = bridge_pool::get_key_from_hash(&transfer.keccak256());
        self.state
            .read(&pending_key)
            .expect("Reading from storage should not fail")
            .zip(Some(pending_key))
    }

    /// Valdidate an [`EthereumEvent`]'s nonce against the current
    /// state of the ledger.
    ///
    /// # Event kinds
    ///
    /// In this section, we shall describe the checks perform for
    /// each kind of relevant Ethereum event.
    ///
    /// ## Transfers to Ethereum
    ///
    /// We need to check if the nonce in the event corresponds to
    /// the most recent bridge pool nonce. Unless the nonces match,
    /// no state updates derived from the event should be applied.
    /// In case the nonces are different, we reject the event, and
    /// thus the inclusion of its container Ethereum events vote
    /// extension.
    ///
    /// ## Transfers to Namada
    ///
    /// For a transfers to Namada event to be considered valid,
    /// the nonce of this kind of event must not be lower than
    /// the one stored in Namada.
    pub fn validate_eth_event_nonce(&self, event: &EthereumEvent) -> bool {
        match event {
            EthereumEvent::TransfersToEthereum {
                nonce: ext_nonce, ..
            } => {
                let current_bp_nonce = self.get_bridge_pool_nonce();
                if &current_bp_nonce != ext_nonce {
                    return false;
                }
            }
            EthereumEvent::TransfersToNamada {
                nonce: ext_nonce, ..
            } => {
                let next_nam_transfers_nonce =
                    self.get_next_nam_transfers_nonce();
                if &next_nam_transfers_nonce > ext_nonce {
                    return false;
                }
            }
            // consider other ethereum event kinds valid
            _ => {}
        }
        true
    }
}

/// Number of tokens to mint after receiving a "transfer
/// to Namada" Ethereum event.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct EthAssetMint {
    /// Amount of NUTs to mint.
    pub nut_amount: token::Amount,
    /// Amount of wrapped ERC20s to mint.
    pub erc20_amount: token::Amount,
}

impl EthAssetMint {
    /// Check if NUTs should be minted.
    #[inline]
    pub fn should_mint_nuts(&self) -> bool {
        !self.nut_amount.is_zero()
    }

    /// Check if ERC20s should be minted.
    #[inline]
    pub fn should_mint_erc20s(&self) -> bool {
        !self.erc20_amount.is_zero()
    }
}
