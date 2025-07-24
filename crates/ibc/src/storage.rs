//! Functions for IBC-related data to access the storage

use std::str::FromStr;

use ibc::apps::nft_transfer::types::{PrefixedClassId, TokenId};
use ibc::core::client::types::Height;
use ibc::core::host::types::identifiers::{
    ChannelId, ClientId, ConnectionId, PortId, Sequence,
};
use ibc::core::host::types::path::{
    AckPath, ChannelEndPath, ClientConnectionPath, ClientConsensusStatePath,
    ClientStatePath, CommitmentPath, ConnectionPath, Path, PortPath,
    ReceiptPath, SeqAckPath, SeqRecvPath, SeqSendPath, UpgradeClientStatePath,
    UpgradeConsensusStatePath,
};
use ibc_middleware_packet_forward::InFlightPacketKey;
use namada_core::address::{Address, InternalAddress};
use namada_core::storage::{DbKeySeg, Key, KeySeg};
use namada_core::token::Amount;
use namada_events::EmitEvents;
pub use namada_state::{Error, Result};
use namada_state::{StorageRead, StorageWrite};
use namada_systems::trans_token;

use crate::event::TOKEN_EVENT_DESCRIPTOR;
use crate::parameters::IbcParameters;
use crate::trace::{ibc_token, ibc_token_for_nft};

const CLIENTS_COUNTER_PREFIX: &str = "clients";
const CONNECTIONS_COUNTER_PREFIX: &str = "connections";
const CHANNELS_COUNTER_PREFIX: &str = "channelEnds";
const COUNTER_SEG: &str = "counter";
const TRACE: &str = "ibc_trace";
const NFT_CLASS: &str = "nft_class";
const NFT_METADATA: &str = "nft_meta";
const PARAMS: &str = "params";
const MINT_LIMIT: &str = "mint_limit";
const MINT: &str = "mint";
const THROUGHPUT_LIMIT: &str = "throughput_limit";
const DEPOSIT: &str = "deposit";
const WITHDRAW: &str = "withdraw";
const UNLIMITED: &str = "unlimited";

/// Mint IBC tokens. This function doesn't emit event (see
/// `mint_tokens_and_emit_event` below)
pub fn mint_tokens<S, Token>(
    storage: &mut S,
    target: &Address,
    token: &Address,
    amount: Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
    Token: trans_token::Keys + trans_token::Read<S> + trans_token::Write<S>,
{
    Token::credit_tokens(storage, token, target, amount)?;

    let minter_key = Token::minter_key(token);
    StorageWrite::write(
        storage,
        &minter_key,
        Address::Internal(InternalAddress::Ibc),
    )
}

/// Mint tokens, and emit an IBC token mint event.
pub fn mint_tokens_and_emit_event<S, Token>(
    storage: &mut S,
    target: &Address,
    token: &Address,
    amount: Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite + EmitEvents,
    Token: trans_token::Keys
        + trans_token::Read<S>
        + trans_token::Write<S>
        + trans_token::Events<S>,
{
    mint_tokens::<S, Token>(storage, target, token, amount)?;

    Token::emit_mint_event(
        storage,
        TOKEN_EVENT_DESCRIPTOR.into(),
        token,
        amount,
        target,
    )?;

    Ok(())
}

/// Burn tokens, and emit an IBC token burn event.
pub fn burn_tokens<S, Token>(
    storage: &mut S,
    target: &Address,
    token: &Address,
    amount: Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite + EmitEvents,
    Token:
        trans_token::Read<S> + trans_token::Write<S> + trans_token::Events<S>,
{
    Token::burn_tokens(storage, token, target, amount)?;

    Token::emit_burn_event(
        storage,
        TOKEN_EVENT_DESCRIPTOR.into(),
        token,
        amount,
        target,
    )?;

    Ok(())
}

/// Returns a key of the IBC-related data
pub fn ibc_key(path: impl AsRef<str>) -> Result<Key> {
    let path = Key::parse(path)?;
    let addr = Address::Internal(InternalAddress::Ibc);
    let key = Key::from(addr.to_db_key());
    Ok(key.join(&path))
}

/// Returns a key of the IBC client counter
pub fn client_counter_key() -> Key {
    let path = format!("{}/{}", CLIENTS_COUNTER_PREFIX, COUNTER_SEG);
    ibc_key(path).expect("Creating a key for the client counter shouldn't fail")
}

/// Returns a key of the IBC connection counter
pub fn connection_counter_key() -> Key {
    let path = format!("{}/{}", CONNECTIONS_COUNTER_PREFIX, COUNTER_SEG);
    ibc_key(path)
        .expect("Creating a key for the connection counter shouldn't fail")
}

/// Returns a key of the IBC channel counter
pub fn channel_counter_key() -> Key {
    let path = format!("{}/{}", CHANNELS_COUNTER_PREFIX, COUNTER_SEG);
    ibc_key(path)
        .expect("Creating a key for the channel counter shouldn't fail")
}

/// Returns a key for the client state
pub fn client_state_key(client_id: &ClientId) -> Key {
    let path = Path::ClientState(ClientStatePath(client_id.clone()));
    ibc_key(path.to_string())
        .expect("Creating a key for the client state shouldn't fail")
}

/// Returns a key for the consensus state
pub fn consensus_state_key(client_id: &ClientId, height: Height) -> Key {
    let path = Path::ClientConsensusState(ClientConsensusStatePath {
        client_id: client_id.clone(),
        revision_number: height.revision_number(),
        revision_height: height.revision_height(),
    });
    ibc_key(path.to_string())
        .expect("Creating a key for the consensus state shouldn't fail")
}

/// Returns a key prefix for the consensus state
pub fn consensus_state_prefix(client_id: &ClientId) -> Key {
    let path = Path::ClientConsensusState(ClientConsensusStatePath {
        client_id: client_id.clone(),
        revision_number: 0,
        revision_height: 0,
    });
    let suffix = "/0-0".to_string();
    let path = path.to_string();
    let prefix = path.strip_suffix(&suffix).expect("The suffix should exist");
    ibc_key(prefix)
        .expect("Creating a key prefix of the consensus state shouldn't fail")
}

/// Returns a key for the upgraded client state
pub fn upgraded_client_state_key(upgraded_height: Height) -> Key {
    let path = Path::UpgradeClientState(
        UpgradeClientStatePath::new_with_default_path(
            upgraded_height.revision_height(),
        ),
    );
    ibc_key(path.to_string())
        .expect("Creating a key for the upgraded client state shouldn't fail")
}

/// Returns a key for the upgraded consensus state
pub fn upgraded_consensus_state_key(upgraded_height: Height) -> Key {
    let path = Path::UpgradeConsensusState(
        UpgradeConsensusStatePath::new_with_default_path(
            upgraded_height.revision_height(),
        ),
    );
    ibc_key(path.to_string()).expect(
        "Creating a key for the upgraded consensus state shouldn't fail",
    )
}

/// Returns a key for the connection end
pub fn connection_key(conn_id: &ConnectionId) -> Key {
    let path = Path::Connection(ConnectionPath(conn_id.clone()));
    ibc_key(path.to_string())
        .expect("Creating a key for the connection shouldn't fail")
}

/// Returns a key for the channel end
pub fn channel_key(port_id: &PortId, channel_id: &ChannelId) -> Key {
    let path =
        Path::ChannelEnd(ChannelEndPath(port_id.clone(), channel_id.clone()));
    ibc_key(path.to_string())
        .expect("Creating a key for the channel shouldn't fail")
}

/// Returns a key for the connection list
pub fn client_connections_key(client_id: &ClientId) -> Key {
    let path = Path::ClientConnection(ClientConnectionPath(client_id.clone()));
    ibc_key(path.to_string())
        .expect("Creating a key for the channel shouldn't fail")
}

/// Returns a key for the port
pub fn port_key(port_id: &PortId) -> Key {
    let path = Path::Ports(PortPath(port_id.clone()));
    ibc_key(path.to_string())
        .expect("Creating a key for the port shouldn't fail")
}

/// Returns a key for nextSequenceSend
pub fn next_sequence_send_key(port_id: &PortId, channel_id: &ChannelId) -> Key {
    let path = Path::SeqSend(SeqSendPath(port_id.clone(), channel_id.clone()));
    ibc_key(path.to_string())
        .expect("Creating a key for nextSequenceSend shouldn't fail")
}

/// Returns a key for nextSequenceRecv
pub fn next_sequence_recv_key(port_id: &PortId, channel_id: &ChannelId) -> Key {
    let path = Path::SeqRecv(SeqRecvPath(port_id.clone(), channel_id.clone()));
    ibc_key(path.to_string())
        .expect("Creating a key for nextSequenceRecv shouldn't fail")
}

/// Returns a key for nextSequenceAck
pub fn next_sequence_ack_key(port_id: &PortId, channel_id: &ChannelId) -> Key {
    let path = Path::SeqAck(SeqAckPath(port_id.clone(), channel_id.clone()));
    ibc_key(path.to_string())
        .expect("Creating a key for nextSequenceAck shouldn't fail")
}

/// Returns a key for the commitment
pub fn commitment_key(
    port_id: &PortId,
    channel_id: &ChannelId,
    sequence: Sequence,
) -> Key {
    let path = Path::Commitment(CommitmentPath {
        port_id: port_id.clone(),
        channel_id: channel_id.clone(),
        sequence,
    });
    ibc_key(path.to_string())
        .expect("Creating a key for the commitment shouldn't fail")
}

/// Returns a key for the receipt
pub fn receipt_key(
    port_id: &PortId,
    channel_id: &ChannelId,
    sequence: Sequence,
) -> Key {
    let path = Path::Receipt(ReceiptPath {
        port_id: port_id.clone(),
        channel_id: channel_id.clone(),
        sequence,
    });
    ibc_key(path.to_string())
        .expect("Creating a key for the receipt shouldn't fail")
}

/// Returns a key for the ack
pub fn ack_key(
    port_id: &PortId,
    channel_id: &ChannelId,
    sequence: Sequence,
) -> Key {
    let path = Path::Ack(AckPath {
        port_id: port_id.clone(),
        channel_id: channel_id.clone(),
        sequence,
    });
    ibc_key(path.to_string())
        .expect("Creating a key for the ack shouldn't fail")
}

/// Returns a key for the timestamp for the client update
pub fn client_update_timestamp_key(client_id: &ClientId) -> Key {
    let path = format!("clients/{}/update_timestamp", client_id);
    ibc_key(path).expect("Creating a key for the ack shouldn't fail")
}

/// Returns a key for the timestamp for the client update
pub fn client_update_height_key(client_id: &ClientId) -> Key {
    let path = format!("clients/{}/update_height", client_id);
    ibc_key(path).expect("Creating a key for the ack shouldn't fail")
}

/// Returns a key for the NFT class
pub fn nft_class_key(class_id: &PrefixedClassId) -> Key {
    let ibc_token = ibc_token(class_id.to_string());
    let path = format!("{NFT_CLASS}/{ibc_token}");
    ibc_key(path).expect("Creating a key for the NFT class shouldn't fail")
}

/// Returns a key for the NFT metadata
pub fn nft_metadata_key(class_id: &PrefixedClassId, token_id: &TokenId) -> Key {
    let ibc_token = ibc_token_for_nft(class_id, token_id);
    let path = format!("{NFT_METADATA}/{ibc_token}");
    ibc_key(path).expect("Creating a key for the NFT metadata shouldn't fail")
}

/// Returns a client ID from the given client key `#IBC/clients/<client_id>`
pub fn client_id(key: &Key) -> Result<ClientId> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(client_id),
            ..,
        ] if addr == &Address::Internal(InternalAddress::Ibc)
            && prefix == "clients" =>
        {
            ClientId::from_str(&client_id.raw())
                .map_err(|e| Error::new_alloc(e.to_string()))
        }
        _ => Err(Error::new_alloc(format!(
            "The key doesn't have a client ID: {}",
            key
        ))),
    }
}

/// Returns the height from the given consensus state key
/// `#IBC/clients/<client_id>/consensusState/0-<height>`
pub fn consensus_height(key: &Key) -> Result<Height> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(_client_id),
            DbKeySeg::StringSeg(module),
            DbKeySeg::StringSeg(height),
        ] if addr == &Address::Internal(InternalAddress::Ibc)
            && prefix == "clients"
            && module == "consensusStates" =>
        {
            Height::from_str(height)
                .map_err(|e| Error::new_alloc(e.to_string()))
        }
        _ => Err(Error::new_alloc(format!(
            "The key doesn't have a consensus height: {}",
            key
        ))),
    }
}

/// Returns a connection ID from the given connection key
/// `#IBC/connections/<conn_id>`
pub fn connection_id(key: &Key) -> Result<ConnectionId> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(conn_id),
        ] if addr == &Address::Internal(InternalAddress::Ibc)
            && prefix == "connections" =>
        {
            ConnectionId::from_str(&conn_id.raw())
                .map_err(|e| Error::new_alloc(e.to_string()))
        }
        _ => Err(Error::new_alloc(format!(
            "The key doesn't have a connection ID: {}",
            key
        ))),
    }
}

/// Returns a pair of port ID and channel ID from the given channel/sequence key
/// `#IBC/<prefix>/ports/<port_id>/channels/<channel_id>`
pub fn port_channel_id(key: &Key) -> Result<(PortId, ChannelId)> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(module0),
            DbKeySeg::StringSeg(port),
            DbKeySeg::StringSeg(module1),
            DbKeySeg::StringSeg(channel),
        ] if addr == &Address::Internal(InternalAddress::Ibc)
            && (prefix == "channelEnds"
                || prefix == "nextSequenceSend"
                || prefix == "nextSequenceRecv"
                || prefix == "nextSequenceAck")
            && module0 == "ports"
            && module1 == "channels" =>
        {
            let port_id = PortId::from_str(&port.raw())
                .map_err(|e| Error::new_alloc(e.to_string()))?;
            let channel_id = ChannelId::from_str(&channel.raw())
                .map_err(|e| Error::new_alloc(e.to_string()))?;
            Ok((port_id, channel_id))
        }
        _ => Err(Error::new_alloc(format!(
            "The key doesn't have port ID and channel ID: Key {}",
            key
        ))),
    }
}

/// Returns a tuple of port ID, channel ID and Sequence from the given packet
/// info key `#IBC/<info_prefix>/ports/<port_id>/channels/<channel_id>/
/// sequences/<sequence>`
pub fn port_channel_sequence_id(
    key: &Key,
) -> Result<(PortId, ChannelId, Sequence)> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(module0),
            DbKeySeg::StringSeg(port_id),
            DbKeySeg::StringSeg(module1),
            DbKeySeg::StringSeg(channel_id),
            DbKeySeg::StringSeg(module2),
            DbKeySeg::StringSeg(seq_index),
        ] if addr == &Address::Internal(InternalAddress::Ibc)
            && (prefix == "commitments"
                || prefix == "receipts"
                || prefix == "acks")
            && module0 == "ports"
            && module1 == "channels"
            && module2 == "sequences" =>
        {
            let port_id = PortId::from_str(&port_id.raw())
                .map_err(|e| Error::new_alloc(e.to_string()))?;
            let channel_id = ChannelId::from_str(&channel_id.raw())
                .map_err(|e| Error::new_alloc(e.to_string()))?;
            let seq = Sequence::from_str(&seq_index.raw())
                .map_err(|e| Error::new_alloc(e.to_string()))?;
            Ok((port_id, channel_id, seq))
        }
        _ => Err(Error::new_alloc(format!(
            "The key doesn't have port ID, channel ID and sequence number: \
             Key {}",
            key,
        ))),
    }
}

/// Returns a port ID from the given port key `#IBC/ports/<port_id>`
pub fn port_id(key: &Key) -> Result<PortId> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(port_id),
            ..,
        ] if addr == &Address::Internal(InternalAddress::Ibc)
            && prefix == "ports" =>
        {
            PortId::from_str(&port_id.raw())
                .map_err(|e| Error::new_alloc(e.to_string()))
        }
        _ => Err(Error::new_alloc(format!(
            "The key doesn't have a port ID: Key {}",
            key
        ))),
    }
}

/// The storage key prefix to get the denom/class name with the hashed IBC
/// denom/class. The address is given as string because the given address could
/// be non-Namada token.
pub fn ibc_trace_key_prefix(addr: Option<String>) -> Key {
    let prefix = Key::from(Address::Internal(InternalAddress::Ibc).to_db_key())
        .push(&TRACE.to_string().to_db_key())
        .expect("Cannot obtain a storage key");

    if let Some(addr) = addr {
        prefix
            .push(&addr.to_db_key())
            .expect("Cannot obtain a storage key")
    } else {
        prefix
    }
}

/// The storage key to get the denom name with the hashed IBC denom. The address
/// is given as string because the given address could be non-Namada token.
pub fn ibc_trace_key(
    addr: impl AsRef<str>,
    token_hash: impl AsRef<str>,
) -> Key {
    ibc_trace_key_prefix(Some(addr.as_ref().to_string()))
        .push(&token_hash.as_ref().to_string().to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Returns true if the given key is for IBC
pub fn is_ibc_key(key: &Key) -> bool {
    matches!(&key.segments[0],
             DbKeySeg::AddressSeg(addr) if *addr == Address::Internal(InternalAddress::Ibc))
}

/// Checks if the key is an IBC commitment key
pub fn is_ibc_commitment_key(key: &Key) -> Option<CommitmentPath> {
    let addr = Address::Internal(InternalAddress::Ibc);
    let ibc_addr_key = Key::from(addr.to_db_key());
    let suffix = key.split_prefix(&ibc_addr_key)??;
    if let Ok(Path::Commitment(path)) = Path::from_str(&suffix.to_string()) {
        Some(path)
    } else {
        None
    }
}

/// Returns the owner and the token hash if the given key is the denom key
pub fn is_ibc_trace_key(key: &Key) -> Option<(String, String)> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(owner),
            DbKeySeg::StringSeg(hash),
        ] => {
            if addr == &Address::Internal(InternalAddress::Ibc)
                && prefix == TRACE
            {
                Some((owner.clone(), hash.clone()))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Returns true if the given key is for an IBC counter for clients,
/// connections, or channelEnds
pub fn is_ibc_counter_key(key: &Key) -> bool {
    matches!(&key.segments[..],
    [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(prefix), DbKeySeg::StringSeg(counter)]
        if addr == &Address::Internal(InternalAddress::Ibc)
            && (prefix == CLIENTS_COUNTER_PREFIX
                || prefix == CONNECTIONS_COUNTER_PREFIX
                || prefix == CHANNELS_COUNTER_PREFIX) && counter == COUNTER_SEG
            )
}

/// Returns a key of IBC parameters
pub fn params_key() -> Key {
    Key::from(Address::Internal(InternalAddress::Ibc).to_db_key())
        .push(&PARAMS.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Returns a key of the mint limit for the token
pub fn mint_limit_key(token: &Address) -> Key {
    Key::from(Address::Internal(InternalAddress::Ibc).to_db_key())
        .push(&MINT_LIMIT.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
        // Set as String to avoid checking the token address
        .push(&token.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Get the mint limit and the throughput limit for the token. If they don't
/// exist in the storage, the default limits are loaded from IBC parameters
pub fn get_limits<S: StorageRead>(
    storage: &S,
    token: &Address,
) -> Result<(Amount, Amount)> {
    let mint_limit_key = mint_limit_key(token);
    let mint_limit: Option<Amount> = storage.read(&mint_limit_key)?;
    let throughput_limit_key = throughput_limit_key(token);
    let throughput_limit: Option<Amount> =
        storage.read(&throughput_limit_key)?;
    Ok(match (mint_limit, throughput_limit) {
        (Some(ml), Some(tl)) => (ml, tl),
        _ => {
            let params: IbcParameters = storage
                .read(&params_key())?
                .expect("Parameters should be stored");
            (
                mint_limit.unwrap_or(params.default_rate_limits.mint_limit),
                throughput_limit.unwrap_or(
                    params.default_rate_limits.throughput_per_epoch_limit,
                ),
            )
        }
    })
}

/// Returns a key of the IBC mint amount for the token
pub fn mint_amount_key(token: &Address) -> Key {
    Key::from(Address::Internal(InternalAddress::Ibc).to_db_key())
        .push(&MINT.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
        // Set as String to avoid checking the token address
        .push(&token.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Returns a key of the per-epoch throughput limit for the token
pub fn throughput_limit_key(token: &Address) -> Key {
    Key::from(Address::Internal(InternalAddress::Ibc).to_db_key())
        .push(&THROUGHPUT_LIMIT.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
        // Set as String to avoid checking the token address
        .push(&token.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Returns a key of the IBC unlimited channel
pub fn unlimited_channel_key(channel_id: &ChannelId) -> Key {
    Key::from(Address::Internal(InternalAddress::Ibc).to_db_key())
        .with_segment(UNLIMITED.to_string())
        .with_segment(channel_id.to_string())
}

/// Returns a prefix of the per-epoch deposit
pub fn deposit_prefix() -> Key {
    Key::from(Address::Internal(InternalAddress::Ibc).to_db_key())
        .push(&DEPOSIT.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Returns a key of the per-epoch deposit for the token
pub fn deposit_key(token: &Address) -> Key {
    deposit_prefix()
        // Set as String to avoid checking the token address
        .push(&token.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Returns a prefix of the per-epoch withdraw
pub fn withdraw_prefix() -> Key {
    Key::from(Address::Internal(InternalAddress::Ibc).to_db_key())
        .push(&WITHDRAW.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Returns a key of the per-epoch withdraw for the token
pub fn withdraw_key(token: &Address) -> Key {
    withdraw_prefix()
        // Set as String to avoid checking the token address
        .push(&token.to_string().to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Get a middleware key prefix.
pub fn middlewares_prefix() -> Key {
    const MIDDLEWARES_SUBKEY: &str = "middleware";

    let key: Key = namada_core::address::IBC.to_db_key().into();
    key.with_segment(MIDDLEWARES_SUBKEY.to_string())
}

/// Get the Namada storage key associated with the provided
/// [`InFlightPacketKey`].
pub fn inflight_packet_key(inflight_packet_key: &InFlightPacketKey) -> Key {
    const PFM_SUBKEY: &str = "pfm";

    middlewares_prefix()
        .with_segment(PFM_SUBKEY.to_string())
        .with_segment(inflight_packet_key.port.to_string())
        .with_segment(inflight_packet_key.channel.to_string())
        .with_segment(inflight_packet_key.sequence.to_string())
}
