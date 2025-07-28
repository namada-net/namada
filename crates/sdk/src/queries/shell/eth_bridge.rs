//! Ethereum bridge related shell queries.

use std::borrow::Cow;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::address::Address;
use namada_core::arith::checked;
use namada_core::chain::{BlockHeight, Epoch};
use namada_core::collections::{HashMap, HashSet};
use namada_core::eth_abi::{Encode, EncodeCell};
use namada_core::eth_bridge_pool::{PendingTransfer, PendingTransferAppendix};
use namada_core::ethereum_events::{
    EthAddress, EthereumEvent, TransferToEthereum,
};
use namada_core::keccak::KeccakHash;
use namada_core::storage::{DbKeySeg, Key};
use namada_core::token::Amount;
use namada_core::voting_power::FractionalVotingPower;
use namada_core::{ethereum_structs, hints};
use namada_ethereum_bridge::event::{BpTransferStatus, BridgePoolTxHash};
use namada_ethereum_bridge::protocol::transactions::votes::{
    EpochedVotingPower, EpochedVotingPowerExt,
};
use namada_ethereum_bridge::storage::bridge_pool::get_key_from_hash;
use namada_ethereum_bridge::storage::eth_bridge_queries::EthBridgeQueries;
use namada_ethereum_bridge::storage::parameters::UpgradeableContract;
use namada_ethereum_bridge::storage::proof::{EthereumProof, sort_sigs};
use namada_ethereum_bridge::storage::vote_tallies::{Keys, eth_msgs_prefix};
use namada_ethereum_bridge::storage::{
    bridge_contract_key, native_erc20_key, vote_tallies,
};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_state::MembershipProof::BridgePool;
use namada_state::{DBIter, DBRead, StorageHasher, StoreRef, StoreType};
use namada_storage::{CustomError, ResultExt, StorageRead};
use namada_vote_ext::validator_set_update::{
    ValidatorSetArgs, VotingPowersMap,
};
use serde::{Deserialize, Serialize};

use crate::borsh::BorshSerializeExt;
use crate::eth_bridge::ethers::abi::AbiDecode;
use crate::governance;
use crate::queries::{EncodedResponseQuery, RequestCtx, RequestQuery};

/// Container for the status of queried transfers to Ethereum.
#[derive(
    Default,
    Debug,
    Clone,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct TransferToEthereumStatus {
    /// The block height at which the query was performed.
    ///
    /// This value may be used to busy wait while a Bridge pool
    /// proof is being constructed for it, such that clients can
    /// safely perform additional actions.
    pub queried_height: BlockHeight,
    /// Transfers in the query whose status it was determined
    /// to be `pending`.
    pub pending: HashSet<KeccakHash>,
    /// Transfers in the query whose status it was determined
    /// to be `relayed`.
    pub relayed: HashSet<KeccakHash>,
    /// Transfers in the query whose status it was determined
    /// to be `expired`.
    pub expired: HashSet<KeccakHash>,
    /// Hashes pertaining to bogus data that might have been queried,
    /// or transfers that were not in the event log, despite having
    /// been relayed to Ethereum or expiring from the Bridge pool.
    pub unrecognized: HashSet<KeccakHash>,
}

/// Contains information about the flow control of some ERC20
/// wrapped asset.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct Erc20FlowControl {
    /// Whether the wrapped asset is whitelisted.
    pub whitelisted: bool,
    /// Total minted supply of some wrapped asset.
    pub supply: Amount,
    /// The token cap of some wrapped asset.
    pub cap: Amount,
}

impl Erc20FlowControl {
    /// Check if the `transferred_amount` exceeds the token caps of some ERC20
    /// asset.
    #[inline]
    #[allow(clippy::result_large_err)]
    pub fn exceeds_token_caps(
        &self,
        transferred_amount: Amount,
    ) -> crate::error::Result<bool> {
        Ok(checked!(self.supply + transferred_amount)? > self.cap)
    }
}

/// Request data to pass to `generate_bridge_pool_proof`.
#[derive(Debug, Clone, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct GenBridgePoolProofReq<'transfers, 'relayer> {
    /// The hashes of the transfers to be relayed.
    pub transfers: Cow<'transfers, [KeccakHash]>,
    /// The address of the relayer to compensate.
    pub relayer: Cow<'relayer, Address>,
    /// Whether to return the appendix of a [`PendingTransfer`].
    pub with_appendix: bool,
}

/// Arguments to pass to `transfer_to_erc`.
pub type TransferToErcArgs = (
    ethereum_structs::ValidatorSetArgs,
    Vec<ethereum_structs::Signature>,
    ethereum_structs::RelayProof,
);

/// Response data returned by `generate_bridge_pool_proof`.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct GenBridgePoolProofRsp {
    /// Ethereum ABI encoded arguments to pass to `transfer_to_erc`.
    pub abi_encoded_args: Vec<u8>,
    /// Appendix data of all requested pending transfers.
    pub appendices: Option<Vec<PendingTransferAppendix<'static>>>,
}

impl GenBridgePoolProofRsp {
    /// Retrieve all [`PendingTransfer`] instances returned from the RPC server.
    pub fn pending_transfers(self) -> impl Iterator<Item = PendingTransfer> {
        TransferToErcArgs::decode(&self.abi_encoded_args)
            .into_iter()
            .flat_map(|(_, _, proof)| proof.transfers)
            .zip(self.appendices.into_iter().flatten())
            .map(|(event, appendix)| {
                let event: TransferToEthereum = event.into();
                PendingTransfer::from_parts(&event, appendix)
            })
    }
}

router! {ETH_BRIDGE,
    // Get the current contents of the Ethereum bridge pool
    ( "pool" / "contents" )
        -> Vec<PendingTransfer> = read_ethereum_bridge_pool,

    // Get the contents of the Ethereum bridge pool covered by
    // the latest signed Merkle tree root.
    ( "pool" / "signed_contents" )
        -> Vec<PendingTransfer> = read_signed_ethereum_bridge_pool,

    // Generate a merkle proof for the inclusion of requested
    // transfers in the Ethereum bridge pool
    ( "pool" / "proof" )
        -> GenBridgePoolProofRsp = (with_options generate_bridge_pool_proof),

    // Iterates over all ethereum events and returns the amount of
    // voting power backing each `TransferToEthereum` event.
    ( "pool" / "transfer_to_eth_progress" )
        -> HashMap<PendingTransfer, FractionalVotingPower>
        = transfer_to_ethereum_progress,

    // Given a list of keccak hashes, check whether they have been
    // relayed, expired or if they are still pending.
    ( "pool" / "transfer_status" )
        -> TransferToEthereumStatus = (with_options pending_eth_transfer_status),

    // Request a proof of a validator set signed off for
    // the given epoch.
    //
    // The request may fail if a proof is not considered complete yet.
    ( "validator_set" / "proof" / [epoch: Epoch] )
        -> EncodeCell<EthereumProof<(Epoch, VotingPowersMap)>>
        = read_valset_upd_proof,

    // Request the set of bridge validators at the given epoch.
    //
    // The request may fail if no validator set exists at that epoch.
    ( "validator_set" / "bridge" / [epoch: Epoch] )
        -> ValidatorSetArgs = read_bridge_valset,

    // Request the set of governance validators at the given epoch.
    //
    // The request may fail if no validator set exists at that epoch.
    ( "validator_set" / "governance" / [epoch: Epoch] )
        -> ValidatorSetArgs = read_governance_valset,

    // Read the address and version of the Ethereum bridge's Bridge
    // smart contract.
    ( "contracts" / "bridge" )
        -> UpgradeableContract = read_bridge_contract,

    // Read the address of the Ethereum bridge's native ERC20
    // smart contract.
    ( "contracts" / "native_erc20" )
        -> EthAddress = read_native_erc20_contract,

    // Read the voting powers map for the requested validator set
    // at the given block height.
    ( "voting_powers" / "height" / [height: BlockHeight] )
        -> VotingPowersMap = voting_powers_at_height,

    // Read the voting powers map for the requested validator set
    // at the given block height.
    ( "voting_powers" / "epoch" / [epoch: Epoch] )
        -> VotingPowersMap = voting_powers_at_epoch,

    // Read the total supply and respective cap of some wrapped
    // ERC20 token in Namada.
    ( "erc20" / "flow_control" / [asset: EthAddress] )
        -> Erc20FlowControl = get_erc20_flow_control,
}

/// Given a list of keccak hashes, check whether they have been
/// relayed, expired or if they are still pending.
fn pending_eth_transfer_status<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    request: &RequestQuery,
) -> namada_storage::Result<EncodedResponseQuery>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut transfer_hashes: HashSet<KeccakHash> =
        BorshDeserialize::try_from_slice(&request.data)
            .into_storage_result()?;

    if transfer_hashes.is_empty() {
        return Ok(Default::default());
    }

    let last_committed_height = ctx.state.in_mem().get_last_block_height();
    let mut status = TransferToEthereumStatus {
        queried_height: last_committed_height,
        ..Default::default()
    };

    // check which transfers in the Bridge pool match the requested hashes
    let merkle_tree = ctx
        .state
        .get_merkle_tree(last_committed_height, Some(StoreType::BridgePool))
        .expect("We should always be able to read the database");
    let stores = merkle_tree.stores();
    let store = match stores.store(&StoreType::BridgePool) {
        StoreRef::BridgePool(store) => store,
        _ => unreachable!(),
    };
    if hints::likely(store.len() > transfer_hashes.len()) {
        transfer_hashes.retain(|hash| {
            let transfer_in_pool = store.contains_key(hash);
            if transfer_in_pool {
                status.pending.insert(hash.clone());
            }
            !transfer_in_pool
        });
    } else {
        for hash in store.keys() {
            if transfer_hashes.swap_remove(hash) {
                status.pending.insert(hash.clone());
            }
            if transfer_hashes.is_empty() {
                break;
            }
        }
    }

    if transfer_hashes.is_empty() {
        let data = status.serialize_to_vec();
        return Ok(EncodedResponseQuery {
            data,
            height: last_committed_height,
            ..Default::default()
        });
    }

    // INVARIANT: transfers that are in the event log will have already
    // been processed and therefore removed from the Bridge pool at the
    // time of this query
    let completed_transfers = ctx.event_log.iter().filter_map(|ev| {
        let Ok(transfer_status) = BpTransferStatus::try_from(ev.kind()) else {
            return None;
        };
        let tx_hash: KeccakHash = ev
            .read_attribute::<BridgePoolTxHash<'_>>()
            .expect("The transfer hash must be available");
        if !transfer_hashes.swap_remove(&tx_hash) {
            return None;
        }
        Some((tx_hash, transfer_status, transfer_hashes.is_empty()))
    });
    for (hash, transfer_status, early_exit) in completed_transfers {
        if hints::likely(matches!(transfer_status, BpTransferStatus::Relayed)) {
            status.relayed.insert(hash.clone());
        } else {
            status.expired.insert(hash.clone());
        }
        if early_exit {
            // early drop of the transfer hashes, in
            // case its storage capacity was big
            transfer_hashes = Default::default();
            break;
        }
    }

    let status = {
        // any remaining transfers are returned as
        // unrecognized hashes
        status.unrecognized = transfer_hashes;
        status
    };
    Ok(EncodedResponseQuery {
        data: status.serialize_to_vec(),
        height: last_committed_height,
        ..Default::default()
    })
}

/// Read the total supply and respective cap of some wrapped
/// ERC20 token in Namada.
fn get_erc20_flow_control<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    asset: EthAddress,
) -> namada_storage::Result<Erc20FlowControl>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let ethbridge_queries = ctx.state.ethbridge_queries();

    let whitelisted = ethbridge_queries.is_token_whitelisted(&asset);
    let supply = ethbridge_queries
        .get_token_supply(&asset)
        .unwrap_or_default();
    let cap = ethbridge_queries.get_token_cap(&asset).unwrap_or_default();

    Ok(Erc20FlowControl {
        whitelisted,
        supply,
        cap,
    })
}

/// Helper function to read a smart contract from storage.
fn read_contract<T, D, H, V, U>(
    key: &Key,
    ctx: RequestCtx<'_, D, H, V, U>,
) -> namada_storage::Result<T>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    let Some(contract) = StorageRead::read(ctx.state, key)? else {
        return Err(namada_storage::Error::SimpleMessage(
            "Failed to read contract: The Ethereum bridge storage is not \
             initialized",
        ));
    };
    Ok(contract)
}

/// Read the address and version of the Ethereum bridge's Bridge
/// smart contract.
#[inline]
fn read_bridge_contract<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<UpgradeableContract>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_contract(&bridge_contract_key(), ctx)
}

/// Read the address of the Ethereum bridge's native ERC20
/// smart contract.
#[inline]
fn read_native_erc20_contract<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<EthAddress>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_contract(&native_erc20_key(), ctx)
}

/// Read the current contents of the Ethereum bridge
/// pool.
fn read_ethereum_bridge_pool<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<Vec<PendingTransfer>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    Ok(read_ethereum_bridge_pool_at_height(
        ctx.state.in_mem().get_last_block_height(),
        ctx,
    ))
}

/// Read the contents of the Ethereum bridge
/// pool covered by the latest signed root.
fn read_signed_ethereum_bridge_pool<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<Vec<PendingTransfer>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // get the latest signed merkle root of the Ethereum bridge pool
    let (_, height) = ctx
        .state
        .ethbridge_queries()
        .get_signed_bridge_pool_root()
        .ok_or(namada_storage::Error::SimpleMessage(
            "No signed root for the Ethereum bridge pool exists in storage.",
        ))
        .into_storage_result()?;
    Ok(read_ethereum_bridge_pool_at_height(height, ctx))
}

/// Read the Ethereum bridge pool contents at a specified height.
fn read_ethereum_bridge_pool_at_height<D, H, V, T>(
    height: BlockHeight,
    ctx: RequestCtx<'_, D, H, V, T>,
) -> Vec<PendingTransfer>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // get the backing store of the merkle tree corresponding
    // at the specified height.
    let merkle_tree = ctx
        .state
        .get_merkle_tree(height, Some(StoreType::BridgePool))
        .expect("We should always be able to read the database");
    let stores = merkle_tree.stores();
    let store = match stores.store(&StoreType::BridgePool) {
        StoreRef::BridgePool(store) => store,
        _ => unreachable!(),
    };

    let transfers: Vec<PendingTransfer> = store
        .keys()
        .map(|hash| {
            let value = ctx
                .state
                .db_read_with_height(&get_key_from_hash(hash), height)
                .unwrap()
                .0
                .unwrap();
            PendingTransfer::try_from_slice(&value).unwrap()
        })
        .collect();
    transfers
}

/// Generate a merkle proof for the inclusion of the
/// requested transfers in the Ethereum bridge pool.
fn generate_bridge_pool_proof<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    request: &RequestQuery,
) -> namada_storage::Result<EncodedResponseQuery>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if let Ok(GenBridgePoolProofReq {
        transfers: transfer_hashes,
        relayer,
        with_appendix,
    }) = BorshDeserialize::try_from_slice(&request.data)
    {
        // get the latest signed merkle root of the Ethereum bridge pool
        let (signed_root, height) = ctx
            .state
            .ethbridge_queries()
            .get_signed_bridge_pool_root()
            .ok_or(namada_storage::Error::SimpleMessage(
                "No signed root for the Ethereum bridge pool exists in \
                 storage.",
            ))
            .into_storage_result()?;

        // make sure a relay attempt won't happen before the new signed
        // root has had time to be generated
        let latest_bp_nonce =
            ctx.state.ethbridge_queries().get_bridge_pool_nonce();
        if latest_bp_nonce != signed_root.data.1 {
            return Err(namada_storage::Error::Custom(CustomError(
                format!(
                    "Mismatch between the nonce in the Bridge pool root proof \
                     ({}) and the latest Bridge pool nonce in storage ({})",
                    signed_root.data.1, latest_bp_nonce,
                )
                .into(),
            )));
        }

        // get the merkle tree corresponding to the above root.
        let tree = ctx
            .state
            .get_merkle_tree(height, Some(StoreType::BridgePool))
            .into_storage_result()?;
        // from the hashes of the transfers, get the actual values.
        let mut missing_hashes = vec![];
        let (keys, values): (Vec<_>, Vec<Vec<u8>>) = transfer_hashes
            .iter()
            .filter_map(|hash| {
                let key = get_key_from_hash(hash);
                match ctx.state.read_bytes(&key) {
                    Ok(Some(bytes)) => Some((key, bytes)),
                    _ => {
                        missing_hashes.push(hash);
                        None
                    }
                }
            })
            .unzip();
        if !missing_hashes.is_empty() {
            return Err(namada_storage::Error::Custom(CustomError(
                format!(
                    "One or more of the provided hashes had no corresponding \
                     transfer in storage: {:?}",
                    missing_hashes
                )
                .into(),
            )));
        }
        let (transfers, appendices) = values.iter().fold(
            (vec![], vec![]),
            |(mut transfers, mut appendices), bytes| {
                let pending = PendingTransfer::try_from_slice(bytes)
                    .expect("Deserializing storage shouldn't fail");
                let eth_transfer = (&pending).into();
                if with_appendix {
                    appendices.push(pending.into_appendix());
                }
                transfers.push(eth_transfer);
                (transfers, appendices)
            },
        );
        // get the membership proof
        match tree.get_sub_tree_existence_proof(
            &keys,
            values.iter().map(|v| v.as_slice()).collect(),
        ) {
            Ok(BridgePool(proof)) => {
                let (validator_args, voting_powers) = ctx
                    .state
                    .ethbridge_queries()
                    .get_bridge_validator_set::<governance::Store<_>>(None);
                let relay_proof = ethereum_structs::RelayProof {
                    transfers,
                    pool_root: signed_root.data.0.0,
                    proof: proof.proof.into_iter().map(|hash| hash.0).collect(),
                    proof_flags: proof.flags,
                    batch_nonce: signed_root.data.1.into(),
                    relayer_address: relayer.to_string(),
                };
                let validator_set: ethereum_structs::ValidatorSetArgs =
                    validator_args.into();
                let signatures =
                    sort_sigs(&voting_powers, &signed_root.signatures);
                let rsp = GenBridgePoolProofRsp {
                    abi_encoded_args: ethers::abi::AbiEncode::encode((
                        validator_set,
                        signatures,
                        relay_proof,
                    )),
                    appendices: with_appendix.then_some(appendices),
                };
                let data = rsp.serialize_to_vec();
                Ok(EncodedResponseQuery {
                    data,
                    height,
                    ..Default::default()
                })
            }
            Ok(_) => unreachable!(),
            Err(e) => Err(namada_storage::Error::new(e)),
        }
    } else {
        Err(namada_storage::Error::SimpleMessage(
            "Could not deserialize transfers",
        ))
    }
}

/// Iterates over all ethereum events
/// and returns the amount of voting power
/// backing each `TransferToEthereum` event.
fn transfer_to_ethereum_progress<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<HashMap<PendingTransfer, FractionalVotingPower>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut pending_events = HashMap::new();
    for (mut key, value) in ctx
        .state
        .iter_prefix(&eth_msgs_prefix())?
        .filter_map(|(k, v, _)| {
            let key = Key::from_str(&k).expect(
                "Iterating over keys from storage shouldn't not yield \
                 un-parsable keys.",
            );
            match key.segments.last() {
                Some(DbKeySeg::StringSeg(ref seg))
                    if seg == Keys::segments().body =>
                {
                    Some((key, v))
                }
                _ => None,
            }
        })
    {
        // we checked above that key is not empty, so this write is fine
        *key.segments.last_mut().unwrap() =
            DbKeySeg::StringSeg(Keys::segments().seen.into());
        // check if the event has been seen
        let is_seen =
            ctx.state.read::<bool>(&key).into_storage_result()?.expect(
                "Iterating over storage should not yield keys without values.",
            );
        if is_seen {
            continue;
        }

        if let Ok(EthereumEvent::TransfersToEthereum { transfers, .. }) =
            EthereumEvent::try_from_slice(&value)
        {
            // read the voting power behind the event
            *key.segments.last_mut().unwrap() =
                DbKeySeg::StringSeg(Keys::segments().voting_power.into());
            let voting_power = ctx
                .state
                .read::<EpochedVotingPower>(&key)
                .into_storage_result()?
                .expect(
                    "Iterating over storage should not yield keys without \
                     values.",
                )
                .fractional_stake::<_, _, governance::Store<_>>(ctx.state);
            for transfer in transfers {
                let key = get_key_from_hash(&transfer.keccak256());
                let transfer = ctx
                    .state
                    .read::<PendingTransfer>(&key)
                    .into_storage_result()?
                    .expect("The transfer must be present in storage");
                pending_events.insert(transfer, voting_power);
            }
        }
    }
    Ok(pending_events)
}

/// Read a validator set update proof from storage.
///
/// This method may fail if a complete proof (i.e. with more than
/// 2/3 of the total voting power behind it) is not available yet.
fn read_valset_upd_proof<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Epoch,
) -> namada_storage::Result<EncodeCell<EthereumProof<(Epoch, VotingPowersMap)>>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if epoch.0 == 0 {
        return Err(namada_storage::Error::Custom(CustomError(
            "Validator set update proofs should only be requested from epoch \
             1 onwards"
                .into(),
        )));
    }
    let current_epoch = ctx.state.in_mem().last_epoch;
    if epoch > current_epoch.next() {
        return Err(namada_storage::Error::Custom(CustomError(
            format!(
                "Requesting validator set update proof for {epoch:?}, but the \
                 last installed epoch is still {current_epoch:?}"
            )
            .into(),
        )));
    }

    if !ctx.state.ethbridge_queries().valset_upd_seen(epoch) {
        return Err(namada_storage::Error::Custom(CustomError(
            format!(
                "Validator set update proof is not yet available for the \
                 queried epoch: {epoch:?}"
            )
            .into(),
        )));
    }

    let valset_upd_keys = vote_tallies::Keys::from(&epoch);
    let proof: EthereumProof<VotingPowersMap> =
        StorageRead::read(ctx.state, &valset_upd_keys.body())?.expect(
            "EthereumProof is seen in storage, therefore it must exist",
        );

    // NOTE: we pass the epoch of the new set of validators
    Ok(proof.map(|set| (epoch, set)).encode())
}

/// Request the set of bridge validators at the given epoch.
///
/// This method may fail if no set of validators exists yet,
/// at that [`Epoch`].
fn read_bridge_valset<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Epoch,
) -> namada_storage::Result<ValidatorSetArgs>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.state.in_mem().last_epoch;
    if epoch > current_epoch.next() {
        Err(namada_storage::Error::Custom(CustomError(
            format!(
                "Requesting Bridge validator set at {epoch:?}, but the last \
                 installed epoch is still {current_epoch:?}"
            )
            .into(),
        )))
    } else {
        Ok(ctx
            .state
            .ethbridge_queries()
            .get_bridge_validator_set::<governance::Store<_>>(Some(epoch))
            .0)
    }
}

/// Request the set of governance validators at the given epoch.
///
/// This method may fail if no set of validators exists yet,
/// at that [`Epoch`].
fn read_governance_valset<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Epoch,
) -> namada_storage::Result<ValidatorSetArgs>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.state.in_mem().last_epoch;
    if epoch > current_epoch.next() {
        Err(namada_storage::Error::Custom(CustomError(
            format!(
                "Requesting Governance validator set at {epoch:?}, but the \
                 last installed epoch is still {current_epoch:?}"
            )
            .into(),
        )))
    } else {
        Ok(ctx
            .state
            .ethbridge_queries()
            .get_governance_validator_set::<governance::Store<_>>(Some(epoch))
            .0)
    }
}

/// Retrieve the consensus validator voting powers at the
/// given [`BlockHeight`].
fn voting_powers_at_height<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    height: BlockHeight,
) -> namada_storage::Result<VotingPowersMap>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let maybe_epoch = ctx.state.get_epoch_at_height(height).unwrap();
    let Some(epoch) = maybe_epoch else {
        return Err(namada_storage::Error::SimpleMessage(
            "The epoch of the requested height does not exist",
        ));
    };
    voting_powers_at_epoch(ctx, epoch)
}

/// Retrieve the consensus validator voting powers at the
/// given [`Epoch`].
fn voting_powers_at_epoch<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Epoch,
) -> namada_storage::Result<VotingPowersMap>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.state.in_mem().get_current_epoch().0;
    if epoch > checked!(current_epoch + 1u64)? {
        return Err(namada_storage::Error::SimpleMessage(
            "The requested epoch cannot be queried",
        ));
    }
    let (_, voting_powers) = ctx
        .state
        .ethbridge_queries()
        .get_bridge_validator_set::<governance::Store<_>>(Some(epoch));
    Ok(voting_powers)
}

#[cfg(test)]
mod test_ethbridge_router {
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;
    use namada_core::address::testing::{established_address_1, nam};
    use namada_core::eth_bridge_pool::{
        GasFee, TransferToEthereum, TransferToEthereumKind,
    };
    use namada_core::voting_power::EthBridgeVotingPower;
    use namada_ethereum_bridge::protocol::transactions::validator_set_update::aggregate_votes;
    use namada_ethereum_bridge::storage::bridge_pool::{
        BridgePoolTree, get_pending_key, get_signed_root_key,
    };
    use namada_ethereum_bridge::storage::proof::BridgePoolRootProof;
    use namada_ethereum_bridge::storage::whitelist;
    use namada_ethereum_bridge::test_utils::GovStore;
    use namada_proof_of_stake::queries::get_total_voting_power;
    use namada_storage::StorageWrite;
    use namada_storage::mockdb::MockDBWriteBatch;
    use namada_vote_ext::validator_set_update;
    use namada_vote_ext::validator_set_update::{
        EthAddrBook, VotingPowersMapExt,
    };

    use super::test_utils::bertha_address;
    use super::*;
    use crate::queries::RPC;
    use crate::queries::testing::TestClient;

    /// Test that reading the bridge validator set works.
    #[tokio::test]
    async fn test_read_consensus_valset() {
        let mut client = TestClient::new(RPC);
        let epoch = Epoch(0);
        assert_eq!(client.state.in_mem().last_epoch, epoch);

        // write validator to storage
        test_utils::init_default_storage(&mut client.state);

        // commit the changes
        client
            .state
            .commit_block_from_batch(MockDBWriteBatch)
            .expect("Test failed");
        let wl_state = client.state.restrict_writes_to_write_log();

        // check the response
        let validator_set = RPC
            .shell()
            .eth_bridge()
            .read_bridge_valset(&client, &epoch)
            .await
            .unwrap();
        let expected = {
            let total_power =
                get_total_voting_power::<_, GovStore<_>>(&wl_state, epoch)
                    .into();

            let voting_powers_map: VotingPowersMap = wl_state
                .ethbridge_queries()
                .get_consensus_eth_addresses::<governance::Store<_>>(epoch)
                .map(|(addr_book, _, power)| (addr_book, power))
                .collect();
            let (validators, voting_powers) = voting_powers_map
                .get_sorted()
                .into_iter()
                .map(|(&EthAddrBook { hot_key_addr, .. }, &power)| {
                    let voting_power: EthBridgeVotingPower =
                        FractionalVotingPower::new(power.into(), total_power)
                            .expect("Fractional voting power should be >1")
                            .try_into()
                            .unwrap();
                    (hot_key_addr, voting_power)
                })
                .unzip();

            ValidatorSetArgs {
                epoch,
                validators,
                voting_powers,
            }
        };

        assert_eq!(validator_set, expected);
    }

    /// Test that when reading an consensus validator set too far ahead,
    /// RPC clients are met with an error.
    #[tokio::test]
    async fn test_read_consensus_valset_too_far_ahead() {
        let mut client = TestClient::new(RPC);
        assert_eq!(client.state.in_mem().last_epoch.0, 0);

        // write validator to storage
        test_utils::init_default_storage(&mut client.state);

        // commit the changes
        client
            .state
            .commit_block_from_batch(MockDBWriteBatch)
            .expect("Test failed");

        // check the response
        let result = RPC
            .shell()
            .eth_bridge()
            .read_bridge_valset(&client, &Epoch(999_999))
            .await;
        let Err(err) = result else {
            panic!("Test failed");
        };

        assert!(
            err.to_string()
                .split_once("but the last installed epoch is still")
                .is_some()
        );
    }

    /// Test that reading a validator set proof works.
    #[tokio::test]
    async fn test_read_valset_upd_proof() {
        let mut client = TestClient::new(RPC);
        assert_eq!(client.state.in_mem().last_epoch.0, 0);

        // write validator to storage
        let keys = test_utils::init_default_storage(&mut client.state);

        // write proof to storage
        let vext = validator_set_update::Vext {
            voting_powers: VotingPowersMap::new(),
            validator_addr: established_address_1(),
            signing_epoch: 0.into(),
        }
        .sign(
            &keys
                .get(&established_address_1())
                .expect("Test failed")
                .eth_bridge,
        );
        let tx_result = aggregate_votes::<_, _, GovStore<_>>(
            &mut client.state,
            validator_set_update::VextDigest::singleton(vext.clone()),
            0.into(),
        )
        .expect("Test failed");
        assert!(!tx_result.changed_keys.is_empty());

        // commit the changes
        client
            .state
            .commit_block_from_batch(MockDBWriteBatch)
            .expect("Test failed");
        let wl_state = client.state.restrict_writes_to_write_log();

        // check the response
        let proof = RPC
            .shell()
            .eth_bridge()
            .read_valset_upd_proof(&client, &Epoch(1))
            .await
            .unwrap();
        let expected = {
            let mut proof =
                EthereumProof::new((1.into(), vext.0.data.voting_powers));
            proof.attach_signature(
                wl_state
                    .ethbridge_queries()
                    .get_eth_addr_book::<governance::Store<_>>(
                        &established_address_1(),
                        Some(0.into()),
                    )
                    .expect("Test failed"),
                vext.0.sig,
            );
            proof.encode()
        };

        assert_eq!(proof, expected);
    }

    /// Test that when reading a validator set proof too far ahead,
    /// RPC clients are met with an error.
    #[tokio::test]
    async fn test_read_valset_upd_proof_too_far_ahead() {
        let mut client = TestClient::new(RPC);
        assert_eq!(client.state.in_mem().last_epoch.0, 0);

        // write validator to storage
        test_utils::init_default_storage(&mut client.state);

        // commit the changes
        client
            .state
            .commit_block_from_batch(MockDBWriteBatch)
            .expect("Test failed");

        // check the response
        let result = RPC
            .shell()
            .eth_bridge()
            .read_valset_upd_proof(&client, &Epoch(999_999))
            .await;
        let Err(err) = result else {
            panic!("Test failed");
        };

        assert!(
            err.to_string()
                .split_once("but the last installed epoch is still")
                .is_some()
        );
    }

    /// Test that reading the bridge pool works
    #[tokio::test]
    async fn test_read_bridge_pool() {
        let mut client = TestClient::new(RPC);

        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client.state.in_mem_mut().block.height = 1.into();
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer), &transfer)
            .expect("Test failed");

        // commit the changes and increase block height
        client.state.commit_block().expect("Test failed");
        client.state.in_mem_mut().block.height += 1;

        // check the response
        let pool = RPC
            .shell()
            .eth_bridge()
            .read_ethereum_bridge_pool(&client)
            .await
            .unwrap();
        assert_eq!(pool, Vec::from([transfer]));
    }

    /// Test that reading the bridge pool always gets
    /// the latest pool
    #[tokio::test]
    async fn test_bridge_pool_updates() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer), &transfer)
            .expect("Test failed");

        // commit the changes and increase block height
        client.state.commit_block().expect("Test failed");
        client.state.in_mem_mut().block.height += 1;

        // update the pool
        client
            .state
            .write_log_mut()
            .delete(&get_pending_key(&transfer))
            .expect("Test failed");
        let mut transfer2 = transfer;
        transfer2.transfer.amount = 1.into();
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer2), &transfer2)
            .expect("Test failed");

        // commit the changes and increase block height
        client.state.commit_block().expect("Test failed");
        client.state.in_mem_mut().block.height += 1;

        // check the response
        let pool = RPC
            .shell()
            .eth_bridge()
            .read_ethereum_bridge_pool(&client)
            .await
            .unwrap();
        assert_eq!(pool, Vec::from([transfer2]));
    }

    /// Test that we can get a merkle proof even if the signed
    /// merkle roots is lagging behind the pool
    #[tokio::test]
    async fn test_get_merkle_proof() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write validator to storage
        test_utils::init_default_storage(&mut client.state);

        // write a transfer into the bridge pool
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer), &transfer)
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = BridgePoolRootProof {
            signatures: Default::default(),
            data: (transfer.keccak256(), 0.into()),
        };
        let written_height = client.state.in_mem().block.height;

        // commit the changes and increase block height
        client.state.commit_block().expect("Test failed");
        client.state.in_mem_mut().block.height += 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer2), transfer2)
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        client
            .state
            .write_log_mut()
            .write(
                &get_signed_root_key(),
                (signed_root.clone(), written_height),
            )
            .expect("Test failed");

        // commit the changes and increase block height
        client.state.commit_block().expect("Test failed");
        client.state.in_mem_mut().block.height += 1;
        let wl_state = client.state.restrict_writes_to_write_log();

        let resp = RPC
            .shell()
            .eth_bridge()
            .generate_bridge_pool_proof(
                &client,
                Some(
                    GenBridgePoolProofReq {
                        transfers: vec![transfer.keccak256()].into(),
                        relayer: Cow::Owned(bertha_address()),
                        with_appendix: false,
                    }
                    .serialize_to_vec(),
                ),
                None,
                false,
            )
            .await
            .unwrap();

        let tree = BridgePoolTree::new(
            transfer.keccak256(),
            BTreeMap::from([(transfer.keccak256(), 1.into())]),
        );
        let proof = tree
            .get_membership_proof(vec![transfer.clone()])
            .expect("Test failed");

        let (validator_args, voting_powers) =
            wl_state
                .ethbridge_queries()
                .get_bridge_validator_set::<governance::Store<_>>(None);
        let relay_proof = ethereum_structs::RelayProof {
            transfers: vec![(&transfer).into()],
            pool_root: signed_root.data.0.0,
            proof: proof.proof.into_iter().map(|hash| hash.0).collect(),
            proof_flags: proof.flags,
            batch_nonce: Default::default(),
            relayer_address: bertha_address().to_string(),
        };
        let signatures = sort_sigs(&voting_powers, &signed_root.signatures);
        let validator_set: ethereum_structs::ValidatorSetArgs =
            validator_args.into();
        let encoded = ethers::abi::AbiEncode::encode((
            validator_set,
            signatures,
            relay_proof,
        ));
        assert_eq!(encoded, resp.data.abi_encoded_args);
    }

    /// Test if the merkle tree including a transfer has not had its
    /// root signed, then we cannot generate a proof.
    #[tokio::test]
    async fn test_cannot_get_proof() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        // write validator to storage
        test_utils::init_default_storage(&mut client.state);

        // write a transfer into the bridge pool
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer), &transfer)
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = BridgePoolRootProof {
            signatures: Default::default(),
            data: (transfer.keccak256(), 0.into()),
        };

        // commit the changes and increase block height
        client
            .state
            .commit_block_from_batch(MockDBWriteBatch)
            .expect("Test failed");
        client.state.in_mem_mut().block.height += 1;

        // update the pool
        let mut transfer2 = transfer;
        transfer2.transfer.amount = 1.into();
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer2), &transfer2)
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        client
            .state
            .write_log_mut()
            .write(&get_signed_root_key(), (signed_root, BlockHeight::from(0)))
            .expect("Test failed");

        // commit the changes and increase block height
        client
            .state
            .commit_block_from_batch(MockDBWriteBatch)
            .expect("Test failed");
        client.state.in_mem_mut().block.height += 1;

        // this is in the pool, but its merkle root has not been signed yet
        let resp = RPC
            .shell()
            .eth_bridge()
            .generate_bridge_pool_proof(
                &client,
                Some(
                    GenBridgePoolProofReq {
                        transfers: vec![transfer2.keccak256()].into(),
                        relayer: Cow::Owned(bertha_address()),
                        with_appendix: false,
                    }
                    .serialize_to_vec(),
                ),
                None,
                false,
            )
            .await;
        // thus proof generation should fail
        assert!(resp.is_err());
    }

    /// Test that the RPC call for bridge pool transfers
    /// covered by a signed merkle root behaves correctly.
    #[tokio::test]
    async fn test_read_signed_bp_transfers() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        // write validator to storage
        test_utils::init_default_storage(&mut client.state);

        // write a transfer into the bridge pool
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer), &transfer)
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = BridgePoolRootProof {
            signatures: Default::default(),
            data: (transfer.keccak256(), 0.into()),
        };
        let written_height = client.state.in_mem().block.height;

        // commit the changes and increase block height
        client.state.commit_block().expect("Test failed");
        client.state.in_mem_mut().block.height += 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer2), transfer2)
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        client
            .state
            .write_log_mut()
            .write(&get_signed_root_key(), (signed_root, written_height))
            .expect("Test failed");

        // commit the changes and increase block height
        client.state.commit_block().expect("Test failed");
        client.state.in_mem_mut().block.height += 1;
        let resp = RPC
            .shell()
            .eth_bridge()
            .read_signed_ethereum_bridge_pool(&client)
            .await
            .unwrap();
        assert_eq!(resp, vec![transfer]);
    }

    /// Test that we can get the backing voting power for
    /// each pending TransferToEthereum event.
    #[tokio::test]
    async fn test_transfer_to_eth_progress() {
        let mut client = TestClient::new(RPC);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        // write validator to storage
        let (_, dummy_validator_stake) = test_utils::default_validator();
        test_utils::init_default_storage(&mut client.state);

        // write a transfer into the bridge pool
        client
            .state
            .write(&get_pending_key(&transfer), &transfer)
            .expect("Test failed");

        let event_transfer: namada_core::ethereum_events::TransferToEthereum =
            (&transfer).into();
        let eth_event = EthereumEvent::TransfersToEthereum {
            nonce: Default::default(),
            transfers: vec![event_transfer.clone()],
            relayer: bertha_address(),
        };
        let eth_msg_key = vote_tallies::Keys::from(&eth_event);
        let voting_power = FractionalVotingPower::HALF;
        client
            .state
            .write_log_mut()
            .write(&eth_msg_key.body(), eth_event)
            .expect("Test failed");
        client
            .state
            .write_log_mut()
            .write(
                &eth_msg_key.voting_power(),
                EpochedVotingPower::from([(
                    0.into(),
                    voting_power * dummy_validator_stake,
                )]),
            )
            .expect("Test failed");
        client
            .state
            .write_log_mut()
            .write(&eth_msg_key.seen(), false)
            .expect("Test failed");
        // commit the changes and increase block height
        client
            .state
            .commit_block_from_batch(MockDBWriteBatch)
            .expect("Test failed");
        client.state.in_mem_mut().block.height += 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer2), transfer2)
            .expect("Test failed");

        // commit the changes and increase block height
        client
            .state
            .commit_block_from_batch(MockDBWriteBatch)
            .expect("Test failed");
        client.state.in_mem_mut().block.height += 1;
        let resp = RPC
            .shell()
            .eth_bridge()
            .transfer_to_ethereum_progress(&client)
            .await
            .unwrap();
        let expected: HashMap<PendingTransfer, FractionalVotingPower> =
            [(transfer, voting_power)].into_iter().collect();
        assert_eq!(expected, resp);
    }

    /// Test if the a transfer has been removed from the
    /// pool (either because it was transferred or timed out),
    /// a proof is not generated for it, even if it was
    /// covered by a signed merkle root at a previous block
    /// height.
    #[tokio::test]
    async fn test_cannot_get_proof_for_removed_transfer() {
        let mut client = TestClient::new(RPC);
        // write validator to storage
        test_utils::init_default_storage(&mut client.state);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer), &transfer)
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = BridgePoolRootProof {
            signatures: Default::default(),
            data: (transfer.keccak256(), 0.into()),
        };
        let written_height = client.state.in_mem().block.height;

        // commit the changes and increase block height
        client.state.commit_block().expect("Test failed");
        client.state.in_mem_mut().block.height += 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer2), transfer2)
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        client
            .state
            .write_log_mut()
            .write(&get_signed_root_key(), (signed_root, written_height))
            .expect("Test failed");

        // commit the changes and increase block height
        client.state.commit_block().expect("Test failed");
        client.state.in_mem_mut().block.height += 1;
        // this was in the pool, covered by an old signed Merkle root.
        let resp = RPC
            .shell()
            .eth_bridge()
            .generate_bridge_pool_proof(
                &client,
                Some(
                    GenBridgePoolProofReq {
                        transfers: vec![transfer.keccak256()].into(),
                        relayer: Cow::Owned(bertha_address()),
                        with_appendix: false,
                    }
                    .serialize_to_vec(),
                ),
                None,
                false,
            )
            .await;
        assert!(resp.is_ok());

        // remove a transfer from the pool.
        client
            .state
            .write_log_mut()
            .delete(&get_pending_key(&transfer))
            .expect("Test failed");

        // this was in the pool, covered by an old signed Merkle root.
        let resp = RPC
            .shell()
            .eth_bridge()
            .generate_bridge_pool_proof(
                &client,
                Some(
                    GenBridgePoolProofReq {
                        transfers: vec![transfer.keccak256()].into(),
                        relayer: Cow::Owned(bertha_address()),
                        with_appendix: false,
                    }
                    .serialize_to_vec(),
                ),
                None,
                false,
            )
            .await;
        // thus proof generation should fail
        assert!(resp.is_err());
    }

    /// Test reading the supply and cap of an ERC20 token.
    #[tokio::test]
    async fn test_get_erc20_flow_control() {
        const ERC20_TOKEN: EthAddress = EthAddress([0; 20]);

        let mut client = TestClient::new(RPC);
        assert_eq!(client.state.in_mem().last_epoch.0, 0);

        // initialize storage
        test_utils::init_default_storage(&mut client.state);

        // check supply - should be 0
        let result = RPC
            .shell()
            .eth_bridge()
            .get_erc20_flow_control(&client, &ERC20_TOKEN)
            .await;
        assert_matches!(
            result,
            Ok(f) if f.supply.is_zero() && f.cap.is_zero()
        );

        // write tokens to storage
        let supply_amount = Amount::native_whole(123);
        let cap_amount = Amount::native_whole(12345);
        let key = whitelist::Key {
            asset: ERC20_TOKEN,
            suffix: whitelist::KeyType::WrappedSupply,
        }
        .into();
        client
            .state
            .write_log_mut()
            .write(&key, supply_amount)
            .expect("Test failed");
        let key = whitelist::Key {
            asset: ERC20_TOKEN,
            suffix: whitelist::KeyType::Cap,
        }
        .into();
        client
            .state
            .write_log_mut()
            .write(&key, cap_amount)
            .expect("Test failed");

        // check that the supply was updated
        let result = RPC
            .shell()
            .eth_bridge()
            .get_erc20_flow_control(&client, &ERC20_TOKEN)
            .await;
        assert_matches!(
            result,
            Ok(f) if f.supply == supply_amount && f.cap == cap_amount
        );
    }

    /// Test that querying the status of the Bridge pool
    /// returns the expected keccak hashes.
    #[tokio::test]
    async fn test_bridge_pool_status() {
        let mut client = TestClient::new(RPC);

        // write a transfer into the bridge pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        client
            .state
            .write_log_mut()
            .write(&get_pending_key(&transfer), transfer.clone())
            .expect("Test failed");

        // write transfers into the event log
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        let mut transfer3 = transfer.clone();
        transfer3.transfer.amount = 2.into();
        client.event_log.log_events(vec![
            crate::eth_bridge::event::EthBridgeEvent::BridgePool {
                tx_hash: transfer2.keccak256(),
                status: crate::eth_bridge::event::BpTransferStatus::Expired,
            }
            .into(),
            crate::eth_bridge::event::EthBridgeEvent::BridgePool {
                tx_hash: transfer3.keccak256(),
                status: crate::eth_bridge::event::BpTransferStatus::Relayed,
            }
            .into(),
        ]);

        // some arbitrary transfer - since it's neither in the
        // Bridge pool nor in the event log, it is assumed it has
        // either been relayed or that it has expired
        let mut transfer4 = transfer.clone();
        transfer4.transfer.amount = 3.into();

        // change block height
        client.state.in_mem_mut().block.height = 1.into();

        // write bridge pool signed root
        {
            let signed_root = BridgePoolRootProof {
                signatures: Default::default(),
                data: (KeccakHash([0; 32]), 0.into()),
            };
            let written_height = client.state.in_mem().block.height;
            client
                .state
                .write_log_mut()
                .write(&get_signed_root_key(), (signed_root, written_height))
                .expect("Test failed");
            client
                .state
                .commit_block_from_batch(MockDBWriteBatch)
                .expect("Test failed");
        }

        // commit storage changes
        client.state.commit_block().expect("Test failed");

        // check transfer statuses
        let status = RPC
            .shell()
            .eth_bridge()
            .pending_eth_transfer_status(
                &client,
                Some(
                    {
                        let mut req = HashSet::new();
                        req.insert(transfer.keccak256());
                        req.insert(transfer2.keccak256());
                        req.insert(transfer3.keccak256());
                        req.insert(transfer4.keccak256());
                        req
                    }
                    .serialize_to_vec(),
                ),
                None,
                false,
            )
            .await
            .unwrap()
            .data;

        assert_eq!(
            status.pending,
            HashSet::from([transfer.keccak256()]),
            "unexpected pending transfers"
        );
        assert_eq!(
            status.expired,
            HashSet::from([transfer2.keccak256()]),
            "unexpected expired transfers"
        );
        assert_eq!(
            status.relayed,
            HashSet::from([transfer3.keccak256()]),
            "unexpected relayed transfers"
        );
        assert_eq!(
            status.unrecognized,
            HashSet::from([transfer4.keccak256()]),
            "unexpected unrecognized transfers"
        );
    }
}

#[cfg(any(feature = "testing", test))]
#[allow(dead_code)]
mod test_utils {
    use namada_core::address::Address;
    #[allow(unused_imports)]
    pub use namada_ethereum_bridge::test_utils::*;

    /// An established user address for testing & development
    pub fn bertha_address() -> Address {
        Address::decode("tnam1qyctxtpnkhwaygye0sftkq28zedf774xc5a2m7st")
            .expect("The token address decoding shouldn't fail")
    }
}
