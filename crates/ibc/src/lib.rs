//! IBC library code

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]
#![cfg_attr(feature = "arbitrary", allow(clippy::disallowed_methods))]

mod actions;
pub mod context;
pub mod event;
mod msg;
mod nft;
pub mod parameters;
pub mod storage;
pub mod trace;
pub mod vp;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::rc::Rc;
use std::str::FromStr;

pub use actions::transfer_over_ibc;
use apps::transfer::types::PORT_ID_STR;
use apps::transfer::types::packet::PacketData;
use borsh::BorshDeserialize;
use context::IbcContext;
pub use context::ValidationParams;
pub use context::common::IbcCommonContext;
pub use context::nft_transfer::NftTransferContext;
pub use context::nft_transfer_mod::NftTransferModule;
use context::router::IbcRouter;
pub use context::storage::{IbcStorageContext, ProofSpec};
pub use context::token_transfer::TokenTransferContext;
pub use context::transfer_mod::{ModuleWrapper, TransferModule};
use ibc::apps::nft_transfer::handler::{
    send_nft_transfer_execute, send_nft_transfer_validate,
};
use ibc::apps::nft_transfer::types::error::NftTransferError;
use ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use ibc::apps::nft_transfer::types::{
    PORT_ID_STR as NFT_PORT_ID_STR, PrefixedClassId, TokenId,
    TracePrefix as NftTracePrefix, ack_success_b64,
    is_receiver_chain_source as is_nft_receiver_chain_source,
};
use ibc::apps::transfer::handler::{
    send_transfer_execute, send_transfer_validate,
};
use ibc::apps::transfer::types::error::TokenTransferError;
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use ibc::apps::transfer::types::{
    PORT_ID_STR as FT_PORT_ID_STR, TracePrefix, is_receiver_chain_source,
};
use ibc::core::channel::types::acknowledgement::AcknowledgementStatus;
use ibc::core::channel::types::commitment::compute_ack_commitment;
use ibc::core::channel::types::msgs::{
    MsgRecvPacket as IbcMsgRecvPacket, PacketMsg,
};
use ibc::core::channel::types::timeout::{TimeoutHeight, TimeoutTimestamp};
use ibc::core::entrypoint::{execute, validate};
use ibc::core::handler::types::error::HandlerError;
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::core::host::types::error::{
    DecodingError, HostError, IdentifierError,
};
use ibc::core::host::types::identifiers::{ChannelId, PortId, Sequence};
use ibc::core::router::types::error::RouterError;
use ibc::primitives::proto::Any;
pub use ibc::*;
use ibc_middleware_packet_forward::PacketMetadata;
use masp_primitives::transaction::Transaction as MaspTransaction;
pub use msg::*;
use namada_core::address::{self, Address};
use namada_core::arith::{CheckedAdd, CheckedSub, checked};
use namada_core::ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use namada_core::ibc::core::channel::types::commitment::{
    AcknowledgementCommitment, PacketCommitment, compute_packet_commitment,
};
pub use namada_core::ibc::*;
use namada_core::masp::{PaymentAddress, TAddrData, addr_taddr, ibc_taddr};
use namada_core::masp_primitives::transaction::components::ValueSum;
use namada_core::token::Amount;
use namada_events::EmitEvents;
use namada_state::{
    DB, DBIter, Error as StorageError, Key, Result as StorageResult, ResultExt,
    State, StorageHasher, StorageRead, StorageWrite, WlState,
};
use namada_systems::ibc::ChangedBalances;
use namada_systems::trans_token;
pub use nft::*;
use prost::Message;
use thiserror::Error;
use trace::{
    convert_to_address, ibc_trace_for_nft,
    is_receiver_chain_source as is_receiver_chain_source_str,
    is_sender_chain_source,
};

use crate::storage::{
    channel_counter_key, client_counter_key, connection_counter_key,
    deposit_prefix, nft_class_key, nft_metadata_key, withdraw_prefix,
};

/// The event type defined in ibc-rs for receiving a token
pub const EVENT_TYPE_PACKET: &str = "fungible_token_packet";
/// The event type defined in ibc-rs for receiving an NFT
pub const EVENT_TYPE_NFT_PACKET: &str = "non_fungible_token_packet";
/// The escrow address for IBC transfer
pub const IBC_ESCROW_ADDRESS: Address = address::IBC;
/// The commitment prefix for the ICS23 commitment proof
pub const COMMITMENT_PREFIX: &str = "ibc";

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("IBC event error: {0}")]
    IbcEvent(DecodingError),
    #[error("Decoding IBC data error")]
    DecodingData,
    #[error("Decoding message error: {0}")]
    DecodingMessage(RouterError),
    #[error("IBC handler error: {0}")]
    Handler(Box<HandlerError>),
    #[error("IBC token transfer error: {0}")]
    TokenTransfer(TokenTransferError),
    #[error("IBC NFT transfer error: {0}")]
    NftTransfer(NftTransferError),
    #[error("Trace error: {0}")]
    Trace(String),
    #[error("Invalid chain ID: {0}")]
    ChainId(IdentifierError),
    #[error("Verifier insertion error: {0}")]
    Verifier(StorageError),
    #[error("Storage read/write error: {0}")]
    Storage(StorageError),
    #[error("IBC error: {0}")]
    Other(String),
}

impl From<Error> for StorageError {
    fn from(value: Error) -> Self {
        StorageError::new(value)
    }
}

struct IbcTransferInfo {
    src_port_id: PortId,
    src_channel_id: ChannelId,
    timeout_height: TimeoutHeight,
    timeout_timestamp: TimeoutTimestamp,
    packet_data: Vec<u8>,
    ibc_traces: Vec<String>,
    amount: Amount,
    receiver: String,
}

impl TryFrom<IbcMsgTransfer> for IbcTransferInfo {
    type Error = StorageError;

    fn try_from(
        message: IbcMsgTransfer,
    ) -> std::result::Result<Self, Self::Error> {
        let packet_data = serde_json::to_vec(&message.packet_data)
            .map_err(StorageError::new)?;
        let ibc_traces = vec![message.packet_data.token.denom.to_string()];
        let amount = message
            .packet_data
            .token
            .amount
            .try_into()
            .into_storage_result()?;
        let receiver = message.packet_data.receiver.to_string();
        Ok(Self {
            src_port_id: message.port_id_on_a,
            src_channel_id: message.chan_id_on_a,
            timeout_height: message.timeout_height_on_b,
            timeout_timestamp: message.timeout_timestamp_on_b,
            packet_data,
            ibc_traces,
            amount,
            receiver,
        })
    }
}

impl TryFrom<IbcMsgNftTransfer> for IbcTransferInfo {
    type Error = StorageError;

    fn try_from(
        message: IbcMsgNftTransfer,
    ) -> std::result::Result<Self, Self::Error> {
        let packet_data = serde_json::to_vec(&message.packet_data)
            .map_err(StorageError::new)?;
        let ibc_traces = message
            .packet_data
            .token_ids
            .0
            .iter()
            .map(|token_id| {
                ibc_trace_for_nft(&message.packet_data.class_id, token_id)
            })
            .collect();
        let receiver = message.packet_data.receiver.to_string();
        Ok(Self {
            src_port_id: message.port_id_on_a,
            src_channel_id: message.chan_id_on_a,
            timeout_height: message.timeout_height_on_b,
            timeout_timestamp: message.timeout_timestamp_on_b,
            packet_data,
            ibc_traces,
            amount: Amount::from_u64(1),
            receiver,
        })
    }
}

/// IBC storage `Keys/Read/Write` implementation
#[derive(Debug)]
pub struct Store<S>(PhantomData<S>);

impl<S> namada_systems::ibc::Read<S> for Store<S>
where
    S: StorageRead,
{
    fn try_extract_masp_tx_from_envelope<Transfer: BorshDeserialize>(
        tx_data: &[u8],
    ) -> StorageResult<Option<masp_primitives::transaction::Transaction>> {
        let msg = decode_message::<Transfer>(tx_data)
            .into_storage_result()
            .ok();
        let tx = if let Some(IbcMessage::Envelope(envelope)) = msg {
            Some(extract_masp_tx_from_envelope(&envelope).ok_or_else(|| {
                StorageError::new_const(
                    "Missing MASP transaction in IBC message",
                )
            })?)
        } else {
            None
        };
        Ok(tx)
    }

    fn apply_ibc_packet<Transfer: BorshDeserialize>(
        storage: &S,
        tx_data: &[u8],
        mut accum: ChangedBalances,
        keys_changed: &BTreeSet<namada_core::storage::Key>,
    ) -> StorageResult<ChangedBalances> {
        let msg = decode_message::<Transfer>(tx_data)
            .into_storage_result()
            .ok();
        match msg {
            None => {}
            // This event is emitted on the sender
            Some(IbcMessage::Transfer(msg)) => {
                // Get the packet commitment from post-storage that corresponds
                // to this event
                let ibc_transfer = IbcTransferInfo::try_from(msg.message)?;
                let receiver = ibc_transfer.receiver.clone();
                let addr = TAddrData::Ibc(receiver.clone());
                accum.decoder.insert(ibc_taddr(receiver), addr);
                accum = apply_transfer_msg(
                    storage,
                    accum,
                    &ibc_transfer,
                    keys_changed,
                )?;
            }
            Some(IbcMessage::NftTransfer(msg)) => {
                // Need to set NFT data because the message doesn't include them
                let message = retrieve_nft_data(storage, msg.message)?;
                let ibc_transfer = IbcTransferInfo::try_from(message)?;
                let receiver = ibc_transfer.receiver.clone();
                let addr = TAddrData::Ibc(receiver.clone());
                accum.decoder.insert(ibc_taddr(receiver), addr);
                accum = apply_transfer_msg(
                    storage,
                    accum,
                    &ibc_transfer,
                    keys_changed,
                )?;
            }
            // This event is emitted on the receiver
            Some(IbcMessage::Envelope(envelope)) => {
                if let MsgEnvelope::Packet(PacketMsg::Recv(msg)) = *envelope {
                    if msg.packet.port_id_on_b.as_str() == PORT_ID_STR {
                        let packet_data = serde_json::from_slice::<PacketData>(
                            &msg.packet.data,
                        )
                        .map_err(StorageError::new)?;
                        let receiver = packet_data.receiver.to_string();
                        let addr = TAddrData::Ibc(receiver.clone());
                        accum.decoder.insert(ibc_taddr(receiver), addr);
                        let ibc_denom = packet_data.token.denom.to_string();
                        let amount = packet_data
                            .token
                            .amount
                            .try_into()
                            .into_storage_result()?;
                        accum = apply_recv_msg(
                            storage,
                            accum,
                            &msg,
                            vec![ibc_denom],
                            amount,
                            keys_changed,
                        )?;
                    } else {
                        let packet_data =
                            serde_json::from_slice::<NftPacketData>(
                                &msg.packet.data,
                            )
                            .map_err(StorageError::new)?;
                        let receiver = packet_data.receiver.to_string();
                        let addr = TAddrData::Ibc(receiver.clone());
                        accum.decoder.insert(ibc_taddr(receiver), addr);
                        let ibc_traces = packet_data
                            .token_ids
                            .0
                            .iter()
                            .map(|token_id| {
                                ibc_trace_for_nft(
                                    &packet_data.class_id,
                                    token_id,
                                )
                            })
                            .collect();
                        accum = apply_recv_msg(
                            storage,
                            accum,
                            &msg,
                            ibc_traces,
                            Amount::from_u64(1),
                            keys_changed,
                        )?;
                    }
                }
            }
        }
        Ok(accum)
    }
}

/// Account id for IBC transfers.
#[derive(Debug)]
pub enum IbcAccountId {
    /// Transparent account.
    Transparent(Address),
    /// Shielded account.
    Shielded(PaymentAddress),
}

impl FromStr for IbcAccountId {
    type Err = HostError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match () {
            // assume we have a transparent addr
            _ if s.starts_with('t') => {
                Ok(IbcAccountId::Transparent(s.parse().map_err(|err| {
                    HostError::Other {
                        description: format!(
                            "Failed to parse IBC transparent address {s:?}: \
                             {err}"
                        ),
                    }
                })?))
            }
            // assume we have a shielded addr
            _ if s.starts_with('z') => {
                Ok(IbcAccountId::Shielded(s.parse().map_err(|err| {
                    HostError::Other {
                        description: format!(
                            "Failed to parse IBC shielded address {s:?}: {err}"
                        ),
                    }
                })?))
            }
            _ => Err(HostError::Other {
                description: format!("Unknown IBC address {s:?}"),
            }),
        }
    }
}

impl fmt::Display for IbcAccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transparent(addr) => write!(f, "{addr}"),
            Self::Shielded(addr) => write!(f, "{addr}"),
        }
    }
}

fn check_ibc_transfer<S>(
    storage: &S,
    ibc_transfer: &IbcTransferInfo,
    keys_changed: &BTreeSet<Key>,
) -> StorageResult<()>
where
    S: StorageRead,
{
    let IbcTransferInfo {
        src_port_id,
        src_channel_id,
        timeout_height,
        timeout_timestamp,
        packet_data,
        ..
    } = ibc_transfer;
    let sequence =
        get_last_sequence_send(storage, src_port_id, src_channel_id)?;
    let commitment_key =
        storage::commitment_key(src_port_id, src_channel_id, sequence);

    if !keys_changed.contains(&commitment_key) {
        return Err(StorageError::new_alloc(format!(
            "Expected IBC transfer didn't happen: Port ID {src_port_id}, \
             Channel ID {src_channel_id}, Sequence {sequence}"
        )));
    }

    // The commitment is also validated in IBC VP. Make sure that for when
    // IBC VP isn't triggered.
    let actual: PacketCommitment = storage
        .read_bytes(&commitment_key)?
        .ok_or(StorageError::new_alloc(format!(
            "Packet commitment doesn't exist: Port ID  {src_port_id}, Channel \
             ID {src_channel_id}, Sequence {sequence}"
        )))?
        .into();
    let expected = compute_packet_commitment(
        packet_data,
        timeout_height,
        timeout_timestamp,
    );
    if actual != expected {
        return Err(StorageError::new_alloc(format!(
            "Packet commitment mismatched: Port ID {src_port_id}, Channel ID \
             {src_channel_id}, Sequence {sequence}"
        )));
    }

    Ok(())
}

// Check that the packet receipt key has been changed
fn check_packet_receiving(
    msg: &IbcMsgRecvPacket,
    keys_changed: &BTreeSet<Key>,
) -> StorageResult<()> {
    let receipt_key = storage::receipt_key(
        &msg.packet.port_id_on_b,
        &msg.packet.chan_id_on_b,
        msg.packet.seq_on_a,
    );
    if !keys_changed.contains(&receipt_key) {
        return Err(StorageError::new_alloc(format!(
            "The packet has not been received: Port ID {}, Channel ID {}, \
             Sequence {}",
            msg.packet.port_id_on_b,
            msg.packet.chan_id_on_b,
            msg.packet.seq_on_a,
        )));
    }
    Ok(())
}

// Apply the given transfer message to the changed balances structure
fn apply_transfer_msg<S>(
    storage: &S,
    mut accum: ChangedBalances,
    ibc_transfer: &IbcTransferInfo,
    keys_changed: &BTreeSet<Key>,
) -> StorageResult<ChangedBalances>
where
    S: StorageRead,
{
    check_ibc_transfer(storage, ibc_transfer, keys_changed)?;

    let IbcTransferInfo {
        ibc_traces,
        src_port_id,
        src_channel_id,
        amount,
        receiver,
        ..
    } = ibc_transfer;

    let receiver = ibc_taddr(receiver.clone());
    for ibc_trace in ibc_traces {
        let token = convert_to_address(ibc_trace).into_storage_result()?;
        let delta = ValueSum::from_pair(token, *amount);
        // If there is a transfer to the IBC account, then deduplicate the
        // balance increase since we already account for it below
        if is_sender_chain_source(ibc_trace, src_port_id, src_channel_id) {
            let ibc_taddr = addr_taddr(address::IBC);
            let post_entry = accum
                .post
                .get(&ibc_taddr)
                .cloned()
                .unwrap_or(ValueSum::zero());
            accum.post.insert(
                ibc_taddr,
                checked!(post_entry - &delta).map_err(StorageError::new)?,
            );
        }
        // Record an increase to the balance of a specific IBC receiver
        let post_entry = accum
            .post
            .get(&receiver)
            .cloned()
            .unwrap_or(ValueSum::zero());
        accum.post.insert(
            receiver,
            checked!(post_entry + &delta).map_err(StorageError::new)?,
        );
    }

    Ok(accum)
}

// Check if IBC message was received successfully in this state transition
fn is_receiving_success<S>(
    storage: &S,
    dst_port_id: &PortId,
    dst_channel_id: &ChannelId,
    sequence: Sequence,
) -> StorageResult<bool>
where
    S: StorageRead,
{
    // Ensure that the event corresponds to the current changes to storage
    let ack_key = storage::ack_key(dst_port_id, dst_channel_id, sequence);
    // If the receive is a success, then the commitment is unique
    let succ_ack_commitment = compute_ack_commitment(
        &AcknowledgementStatus::success(ack_success_b64()).into(),
    );
    Ok(match storage.read_bytes(&ack_key)? {
        // Success happens only if commitment equals the above
        Some(value) => {
            AcknowledgementCommitment::from(value) == succ_ack_commitment
        }
        // Acknowledgement key non-existence is failure
        None => false,
    })
}

// Apply the given write acknowledge to the changed balances structure
fn apply_recv_msg<S>(
    storage: &S,
    mut accum: ChangedBalances,
    msg: &IbcMsgRecvPacket,
    ibc_traces: Vec<String>,
    amount: Amount,
    keys_changed: &BTreeSet<Key>,
) -> StorageResult<ChangedBalances>
where
    S: StorageRead,
{
    // First check that the packet receipt is reflecteed in the state changes
    check_packet_receiving(msg, keys_changed)?;
    // If the transfer was a failure, then enable funds to
    // be withdrawn from the IBC internal address
    if is_receiving_success(
        storage,
        &msg.packet.port_id_on_b,
        &msg.packet.chan_id_on_b,
        msg.packet.seq_on_a,
    )? {
        for ibc_trace in ibc_traces {
            // Only artificially increase the IBC internal address pre-balance
            // if receiving involves minting. We do not do this in the unescrow
            // case since the pre-balance already accounts for the amount being
            // received.
            if !is_receiver_chain_source_str(
                &ibc_trace,
                &msg.packet.port_id_on_a,
                &msg.packet.chan_id_on_a,
            ) {
                // Get the received token
                let token = received_ibc_token(
                    ibc_trace,
                    &msg.packet.port_id_on_a,
                    &msg.packet.chan_id_on_a,
                    &msg.packet.port_id_on_b,
                    &msg.packet.chan_id_on_b,
                )
                .into_storage_result()?;
                let delta = ValueSum::from_pair(token.clone(), amount);
                // Enable funds to be taken from the IBC internal
                // address and be deposited elsewhere
                // Required for the IBC internal Address to release
                // funds
                let ibc_taddr = addr_taddr(address::IBC);
                let pre_entry = accum
                    .pre
                    .get(&ibc_taddr)
                    .cloned()
                    .unwrap_or(ValueSum::zero());
                accum.pre.insert(
                    ibc_taddr,
                    checked!(pre_entry + &delta).map_err(StorageError::new)?,
                );
            }
        }
    }
    Ok(accum)
}

/// Internal transfer data extracted from the wrapping IBC transaction
#[derive(Debug)]
pub struct InternalData<Transfer> {
    /// The transparent transfer that happens in parallel to IBC processes
    pub transparent: Option<Transfer>,
    /// The shielded transaction that happens in parallel to IBC processes
    pub shielded: Option<MaspTransaction>,
    /// IBC tokens that are credited/debited to internal accounts
    pub ibc_tokens: BTreeSet<Address>,
}

/// IBC actions to handle IBC operations
#[derive(Debug)]
pub struct IbcActions<'a, C, Params, Token>
where
    C: IbcCommonContext,
{
    ctx: IbcContext<C, Params>,
    router: IbcRouter<'a>,
    verifiers: Rc<RefCell<BTreeSet<Address>>>,
    _marker: PhantomData<Token>,
}

impl<'a, C, Params, Token> IbcActions<'a, C, Params, Token>
where
    C: IbcCommonContext,
    Params: namada_systems::parameters::Read<C::Storage>,
    Token: trans_token::Keys,
{
    /// Make new IBC actions
    pub fn new(
        ctx: Rc<RefCell<C>>,
        verifiers: Rc<RefCell<BTreeSet<Address>>>,
    ) -> Self {
        Self {
            ctx: IbcContext::new(ctx),
            router: IbcRouter::new(),
            verifiers,
            _marker: PhantomData,
        }
    }

    /// Add a transfer module to the router
    pub fn add_transfer_module(&mut self, module: impl ModuleWrapper + 'a) {
        self.router.add_transfer_module(module)
    }

    /// Set the validation parameters
    pub fn set_validation_params(&mut self, params: ValidationParams) {
        self.ctx.validation_params = params;
    }

    /// Execute according to the message in an IBC transaction or VP
    pub fn execute<Transfer: BorshDeserialize>(
        &mut self,
        tx_data: &[u8],
    ) -> Result<InternalData<Transfer>, Error> {
        let message = decode_message::<Transfer>(tx_data)?;
        let result = match message {
            IbcMessage::Transfer(msg) => {
                let mut token_transfer_ctx = TokenTransferContext::new(
                    self.ctx.inner.clone(),
                    self.verifiers.clone(),
                );
                // Add the source to the set of verifiers
                self.verifiers.borrow_mut().insert(
                    match msg
                        .message
                        .packet_data
                        .sender
                        .as_ref()
                        .parse::<IbcAccountId>()
                        .map_err(|err| Error::TokenTransfer(err.into()))?
                    {
                        IbcAccountId::Transparent(addr) => addr,
                        IbcAccountId::Shielded(_) => address::MASP,
                    },
                );
                if msg.transfer.is_some() {
                    token_transfer_ctx.enable_shielded_transfer();
                }
                // Record the token credited/debited in this transfer
                let denom = msg.message.packet_data.token.denom.to_string();
                let token = convert_to_address(denom)
                    .into_storage_result()
                    .map_err(Error::Storage)?;
                send_transfer_execute(
                    &mut self.ctx,
                    &mut token_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::TokenTransfer)?;
                Ok(InternalData {
                    transparent: msg.transfer,
                    shielded: None,
                    ibc_tokens: [token].into(),
                })
            }
            IbcMessage::NftTransfer(msg) => {
                let mut nft_transfer_ctx =
                    NftTransferContext::<_, Token>::new(self.ctx.inner.clone());
                if msg.transfer.is_some() {
                    nft_transfer_ctx.enable_shielded_transfer();
                }
                // Add the source to the set of verifiers
                self.verifiers.borrow_mut().insert(
                    match msg
                        .message
                        .packet_data
                        .sender
                        .as_ref()
                        .parse::<IbcAccountId>()
                        .map_err(|err| Error::TokenTransfer(err.into()))?
                    {
                        IbcAccountId::Transparent(addr) => addr,
                        IbcAccountId::Shielded(_) => address::MASP,
                    },
                );
                // Record the tokens credited/debited in this NFT transfer
                let tokens = msg
                    .message
                    .packet_data
                    .token_ids
                    .0
                    .iter()
                    .map(|token_id| {
                        convert_to_address(ibc_trace_for_nft(
                            &msg.message.packet_data.class_id,
                            token_id,
                        ))
                        .into_storage_result()
                        .map_err(Error::Storage)
                    })
                    .collect::<Result<_, _>>()?;

                send_nft_transfer_execute(
                    &mut self.ctx,
                    &mut nft_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::NftTransfer)?;
                Ok(InternalData {
                    transparent: msg.transfer,
                    shielded: None,
                    ibc_tokens: tokens,
                })
            }
            IbcMessage::Envelope(envelope) => {
                if let Some(verifier) = get_envelope_verifier(envelope.as_ref())
                {
                    self.verifiers.borrow_mut().insert(
                        match verifier
                            .as_ref()
                            .parse::<IbcAccountId>()
                            .map_err(|err| Error::TokenTransfer(err.into()))?
                        {
                            IbcAccountId::Transparent(addr) => addr,
                            IbcAccountId::Shielded(_) => address::MASP,
                        },
                    );
                }
                execute(&mut self.ctx, &mut self.router, *envelope.clone())
                    .map_err(|e| Error::Handler(Box::new(e)))?;

                // Extract MASP tx from the memo in the packet if needed
                let (masp_tx, tokens) = match &*envelope {
                    MsgEnvelope::Packet(PacketMsg::Recv(msg))
                        if self
                            .is_receiving_success(msg)?
                            .is_some_and(|ack_succ| ack_succ) =>
                    {
                        let ibc_traces = extract_traces_from_recv_msg(msg)
                            .map_err(StorageError::new)
                            .map_err(Error::Storage)?;
                        let mut tokens = BTreeSet::new();
                        for ibc_trace in ibc_traces {
                            // Get the received token
                            let token = received_ibc_token(
                                ibc_trace,
                                &msg.packet.port_id_on_a,
                                &msg.packet.chan_id_on_a,
                                &msg.packet.port_id_on_b,
                                &msg.packet.chan_id_on_b,
                            )
                            .into_storage_result()
                            .map_err(Error::Storage)?;
                            tokens.insert(token);
                        }
                        (extract_masp_tx_from_packet(&msg.packet), tokens)
                    }
                    #[cfg(is_apple_silicon)]
                    MsgEnvelope::Packet(PacketMsg::Ack(msg)) => {
                        // NOTE: This is unneeded but wasm compilation error
                        // happened if deleted on macOS with Apple Silicon
                        let _ = extract_masp_tx_from_packet(&msg.packet);
                        (None, BTreeSet::new())
                    }
                    _ => (None, BTreeSet::new()),
                };
                Ok(InternalData {
                    transparent: None,
                    shielded: masp_tx,
                    ibc_tokens: tokens,
                })
            }
        };
        self.insert_verifiers()?;
        result
    }

    /// Check the result of receiving the packet by checking the packet
    /// acknowledgement
    pub fn is_receiving_success(
        &self,
        msg: &IbcMsgRecvPacket,
    ) -> Result<Option<bool>, Error> {
        let Some(packet_ack) = self
            .ctx
            .inner
            .borrow()
            .packet_ack(
                &msg.packet.port_id_on_b,
                &msg.packet.chan_id_on_b,
                msg.packet.seq_on_a,
            )
            .map_err(|e| Error::Other(e.to_string()))?
        else {
            return Ok(None);
        };
        let success_ack_commitment = compute_ack_commitment(
            &AcknowledgementStatus::success(ack_success_b64()).into(),
        );
        Ok(Some(packet_ack == success_ack_commitment))
    }

    /// Validate according to the message in IBC VP
    pub fn validate<Transfer: BorshDeserialize>(
        &self,
        tx_data: &[u8],
    ) -> Result<(), Error> {
        // Use an empty verifiers set placeholder for validation, this is only
        // needed in actual txs to addresses whose VPs should be triggered
        let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));

        let message = decode_message::<Transfer>(tx_data)?;
        let result = match message {
            IbcMessage::Transfer(msg) => {
                let mut token_transfer_ctx = TokenTransferContext::new(
                    self.ctx.inner.clone(),
                    verifiers.clone(),
                );
                if msg.transfer.is_some() {
                    token_transfer_ctx.enable_shielded_transfer();
                }
                send_transfer_validate(
                    &self.ctx,
                    &token_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::TokenTransfer)
            }
            IbcMessage::NftTransfer(msg) => {
                let mut nft_transfer_ctx =
                    NftTransferContext::<_, Token>::new(self.ctx.inner.clone());
                if msg.transfer.is_some() {
                    nft_transfer_ctx.enable_shielded_transfer();
                }
                send_nft_transfer_validate(
                    &self.ctx,
                    &nft_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::NftTransfer)
            }
            IbcMessage::Envelope(envelope) => {
                validate(&self.ctx, &self.router, *envelope)
                    .map_err(|e| Error::Handler(Box::new(e)))
            }
        };
        self.insert_verifiers()?;
        result
    }

    fn insert_verifiers(&self) -> Result<(), Error> {
        let mut ctx = self.ctx.inner.borrow_mut();
        for verifier in self.verifiers.borrow().iter() {
            ctx.insert_verifier(verifier).map_err(Error::Verifier)?;
        }
        Ok(())
    }
}

fn is_packet_forward(data: &PacketData) -> bool {
    serde_json::from_str::<PacketMetadata>(data.memo.as_ref()).is_ok()
}

// Extract the involved namada address from the packet (either sender or
// receiver) to trigger its vp. Returns None if an address could not be found
fn get_envelope_verifier(
    envelope: &MsgEnvelope,
) -> Option<ibc::primitives::Signer> {
    match envelope {
        MsgEnvelope::Packet(PacketMsg::Recv(msg)) => {
            match msg.packet.port_id_on_b.as_str() {
                FT_PORT_ID_STR => {
                    let packet_data =
                        serde_json::from_slice::<PacketData>(&msg.packet.data)
                            .ok()?;
                    if is_packet_forward(&packet_data) {
                        None
                    } else {
                        Some(packet_data.receiver)
                    }
                }
                NFT_PORT_ID_STR => {
                    serde_json::from_slice::<NftPacketData>(&msg.packet.data)
                        .ok()
                        .map(|packet_data| packet_data.receiver)
                }
                _ => None,
            }
        }
        MsgEnvelope::Packet(PacketMsg::Ack(msg)) => serde_json::from_slice::<
            AcknowledgementStatus,
        >(
            msg.acknowledgement.as_ref(),
        )
        .map_or(None, |ack| {
            if ack.is_successful() {
                None
            } else {
                match msg.packet.port_id_on_a.as_str() {
                    FT_PORT_ID_STR => {
                        serde_json::from_slice::<PacketData>(&msg.packet.data)
                            .ok()
                            .map(|packet_data| packet_data.sender)
                    }
                    NFT_PORT_ID_STR => serde_json::from_slice::<NftPacketData>(
                        &msg.packet.data,
                    )
                    .ok()
                    .map(|packet_data| packet_data.sender),
                    _ => None,
                }
            }
        }),
        MsgEnvelope::Packet(PacketMsg::Timeout(msg)) => {
            match msg.packet.port_id_on_a.as_str() {
                FT_PORT_ID_STR => {
                    serde_json::from_slice::<PacketData>(&msg.packet.data)
                        .ok()
                        .map(|packet_data| packet_data.sender)
                }
                NFT_PORT_ID_STR => {
                    serde_json::from_slice::<NftPacketData>(&msg.packet.data)
                        .ok()
                        .map(|packet_data| packet_data.sender)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Tries to decode transaction data to an `IbcMessage`
pub fn decode_message<Transfer: BorshDeserialize>(
    tx_data: &[u8],
) -> Result<IbcMessage<Transfer>, Error> {
    // ibc-rs message
    if let Ok(any_msg) = Any::decode(tx_data) {
        if let Ok(envelope) = MsgEnvelope::try_from(any_msg.clone()) {
            return Ok(IbcMessage::Envelope(Box::new(envelope)));
        }
        if let Ok(message) = IbcMsgTransfer::try_from(any_msg.clone()) {
            let msg = MsgTransfer {
                message,
                transfer: None,
            };
            return Ok(IbcMessage::Transfer(Box::new(msg)));
        }
        if let Ok(message) = IbcMsgNftTransfer::try_from(any_msg) {
            let msg = MsgNftTransfer {
                message,
                transfer: None,
            };
            return Ok(IbcMessage::NftTransfer(msg));
        }
    }

    // Transfer message with `ShieldingTransfer`
    if let Ok(msg) = MsgTransfer::<Transfer>::try_from_slice(tx_data) {
        return Ok(IbcMessage::Transfer(Box::new(msg)));
    }

    // NFT transfer message with `ShieldingTransfer`
    if let Ok(msg) = MsgNftTransfer::<Transfer>::try_from_slice(tx_data) {
        return Ok(IbcMessage::NftTransfer(msg));
    }

    Err(Error::DecodingData)
}

/// Return the last sequence send
pub fn get_last_sequence_send<S: StorageRead>(
    storage: &S,
    port_id: &PortId,
    channel_id: &ChannelId,
) -> Result<Sequence, StorageError> {
    let seq_key = storage::next_sequence_send_key(port_id, channel_id);
    let next_seq: u64 =
        context::common::read_sequence(storage, &seq_key)?.into();
    if next_seq <= 1 {
        // No transfer heppened
        return Err(StorageError::new_alloc(format!(
            "No IBC transfer happened: Port ID {port_id}, Channel ID \
             {channel_id}",
        )));
    }
    Ok(checked!(next_seq - 1)?.into())
}

fn received_ibc_trace(
    base_trace: impl AsRef<str>,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
) -> Result<String, Error> {
    if *dest_port_id == PortId::transfer() {
        let mut prefixed_denom = base_trace
            .as_ref()
            .parse()
            .map_err(|e: DecodingError| Error::Trace(e.to_string()))?;
        if is_receiver_chain_source(
            src_port_id.clone(),
            src_channel_id.clone(),
            &prefixed_denom,
        ) {
            let prefix =
                TracePrefix::new(src_port_id.clone(), src_channel_id.clone());
            prefixed_denom.remove_trace_prefix(&prefix);
        } else {
            let prefix =
                TracePrefix::new(dest_port_id.clone(), dest_channel_id.clone());
            prefixed_denom.add_trace_prefix(prefix);
        }
        return Ok(prefixed_denom.to_string());
    }

    if let Some((trace_path, base_class_id, token_id)) =
        trace::is_nft_trace(&base_trace)
    {
        let mut class_id = PrefixedClassId {
            trace_path,
            base_class_id: base_class_id
                .parse()
                .map_err(|e: DecodingError| Error::Trace(e.to_string()))?,
        };
        if is_nft_receiver_chain_source(
            src_port_id.clone(),
            src_channel_id.clone(),
            &class_id,
        ) {
            let prefix = NftTracePrefix::new(
                src_port_id.clone(),
                src_channel_id.clone(),
            );
            class_id.remove_trace_prefix(&prefix);
        } else {
            let prefix = NftTracePrefix::new(
                dest_port_id.clone(),
                dest_channel_id.clone(),
            );
            class_id.add_trace_prefix(prefix);
        }
        let token_id: TokenId = token_id
            .parse()
            .map_err(|e: DecodingError| Error::Trace(e.to_string()))?;
        return Ok(format!("{class_id}/{token_id}"));
    }

    Err(Error::Trace(format!(
        "Invalid IBC trace: {}",
        base_trace.as_ref()
    )))
}

/// Get the IbcToken from the source/destination ports and channels
pub fn received_ibc_token(
    ibc_denom: impl AsRef<str>,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
) -> Result<Address, Error> {
    let ibc_trace = received_ibc_trace(
        ibc_denom,
        src_port_id,
        src_channel_id,
        dest_port_id,
        dest_channel_id,
    )?;
    trace::convert_to_address(ibc_trace)
        .map_err(|e| Error::Trace(format!("Invalid base token: {e}")))
}

fn retrieve_nft_data<S: StorageRead>(
    storage: &S,
    message: IbcMsgNftTransfer,
) -> Result<IbcMsgNftTransfer, StorageError> {
    let mut message = message;
    let class_id = &message.packet_data.class_id;
    let nft_class_key = nft_class_key(class_id);
    let nft_class: NftClass =
        storage.read(&nft_class_key)?.ok_or_else(|| {
            StorageError::new_alloc(format!(
                "No NFT class: class_id {class_id}",
            ))
        })?;
    message.packet_data.class_uri = nft_class.class_uri;
    message.packet_data.class_data = nft_class.class_data;

    let mut token_uris = Vec::new();
    let mut token_data = Vec::new();
    for token_id in &message.packet_data.token_ids.as_ref() {
        let nft_metadata_key = nft_metadata_key(class_id, token_id);
        let nft_metadata: NftMetadata =
            storage.read(&nft_metadata_key)?.ok_or_else(|| {
                StorageError::new_alloc(format!(
                    "No NFT metadata: class_id {class_id}, token_id {token_id}",
                ))
            })?;
        // Set the URI and the data if both exists
        if let (Some(uri), Some(data)) =
            (nft_metadata.token_uri, nft_metadata.token_data)
        {
            token_uris.push(uri);
            token_data.push(data);
        }
    }
    if !token_uris.is_empty() {
        message.packet_data.token_uris = Some(token_uris);
        message.packet_data.token_data = Some(token_data);
    }
    Ok(message)
}

/// Initialize storage in the genesis block.
pub fn init_genesis_storage<S>(storage: &mut S)
where
    S: State,
{
    // In ibc-go, u64 like a counter is encoded with big-endian:
    // https://github.com/cosmos/ibc-go/blob/89ffaafb5956a5ea606e1f1bf249c880bea802ed/modules/core/04-channel/keeper/keeper.go#L115

    let init_value = 0_u64;

    // the client counter
    let key = client_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial client counter");

    // the connection counter
    let key = connection_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial connection counter");

    // the channel counter
    let key = channel_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial channel counter");
}

/// Update IBC-related data when finalizing block
pub fn finalize_block<D, H>(
    state: &mut WlState<D, H>,
    _events: &mut impl EmitEvents,
    is_new_epoch: bool,
) -> Result<(), StorageError>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if is_new_epoch {
        clear_throughputs(state)?;
    }
    Ok(())
}

/// Clear the per-epoch throughputs (deposit and withdraw)
fn clear_throughputs<D, H>(
    state: &mut WlState<D, H>,
) -> Result<(), StorageError>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    for prefix in [deposit_prefix(), withdraw_prefix()] {
        let keys: Vec<Key> = state
            .iter_prefix(&prefix)?
            .map(|(key, _, _)| {
                Key::parse(key).expect("The key should be parsable")
            })
            .collect();
        for key in keys {
            state.write(&key, Amount::from(0))?;
        }
    }

    Ok(())
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers ans strategies for IBC
pub mod testing {
    use std::str::FromStr;

    use ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as MsgNftTransfer;
    use ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
    use ibc::apps::nft_transfer::types::{
        ClassData, ClassId, ClassUri, Memo as NftMemo, PrefixedClassId,
        TokenData, TokenId, TokenIds, TokenUri,
    };
    use ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
    use ibc::apps::transfer::types::packet::PacketData;
    use ibc::apps::transfer::types::{
        Amount, BaseDenom, Memo, PrefixedCoin, PrefixedDenom, TracePath,
        TracePrefix,
    };
    use ibc::core::channel::types::timeout::{TimeoutHeight, TimeoutTimestamp};
    use ibc::core::client::types::Height;
    use ibc::core::host::types::identifiers::{ChannelId, PortId};
    use ibc::core::primitives::Signer;
    use ibc::primitives::proto::Any;
    use ibc::primitives::{Timestamp, ToProto};
    use proptest::prelude::{Just, Strategy};
    use proptest::{collection, option, prop_compose, prop_oneof};

    prop_compose! {
        /// Generate an arbitrary port ID
        pub fn arb_ibc_port_id()(id in "[a-zA-Z0-9_+.\\-\\[\\]#<>]{2,128}") -> PortId {
            PortId::new(id).expect("generated invalid port ID")
        }
    }

    prop_compose! {
        /// Generate an arbitrary channel ID
        pub fn arb_ibc_channel_id()(id: u64) -> ChannelId {
            ChannelId::new(id)
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC height
        pub fn arb_ibc_height()(
            revision_number: u64,
            revision_height in 1u64..,
        ) -> Height {
            Height::new(revision_number, revision_height)
                .expect("generated invalid IBC height")
        }
    }

    /// Generate arbitrary timeout data
    pub fn arb_ibc_timeout_data() -> impl Strategy<Value = TimeoutHeight> {
        prop_oneof![
            arb_ibc_height().prop_map(TimeoutHeight::At),
            Just(TimeoutHeight::Never),
        ]
    }

    prop_compose! {
        /// Generate an arbitrary IBC timestamp
        pub fn arb_ibc_timestamp()(nanoseconds: u64) -> TimeoutTimestamp {
            TimeoutTimestamp::At(Timestamp::from_nanoseconds(nanoseconds))
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC memo
        pub fn arb_ibc_memo()(memo in "[a-zA-Z0-9_]*") -> Memo {
            memo.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC NFT memo
        pub fn arb_ibc_nft_memo()(memo in "[a-zA-Z0-9_]*") -> NftMemo {
            memo.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC memo
        pub fn arb_ibc_signer()(signer in "[a-zA-Z0-9_]*") -> Signer {
            signer.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC trace prefix
        pub fn arb_ibc_trace_prefix()(
            port_id in arb_ibc_port_id(),
            channel_id in arb_ibc_channel_id(),
        ) -> TracePrefix {
            TracePrefix::new(port_id, channel_id)
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC trace path
        pub fn arb_ibc_trace_path()(path in collection::vec(arb_ibc_trace_prefix(), 0..10)) -> TracePath {
            TracePath::from(path)
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC base denomination
        pub fn arb_ibc_base_denom()(base_denom in "[a-zA-Z0-9_]+") -> BaseDenom {
            BaseDenom::from_str(&base_denom).expect("generated invalid IBC base denomination")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC prefixed denomination
        pub fn arb_ibc_prefixed_denom()(
            trace_path in arb_ibc_trace_path(),
            base_denom in arb_ibc_base_denom(),
        ) -> PrefixedDenom {
            PrefixedDenom {
                trace_path,
                base_denom,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC amount
        pub fn arb_ibc_amount()(value: [u64; 4]) -> Amount {
            value.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary prefixed coin
        pub fn arb_ibc_prefixed_coin()(
            denom in arb_ibc_prefixed_denom(),
            amount in arb_ibc_amount(),
        ) -> PrefixedCoin {
            PrefixedCoin {
                denom,
                amount,
            }
        }
    }

    prop_compose! {
        /// Generate arbitrary packet data
        pub fn arb_ibc_packet_data()(
            token in arb_ibc_prefixed_coin(),
            sender in arb_ibc_signer(),
            receiver in arb_ibc_signer(),
            memo in arb_ibc_memo(),
        ) -> PacketData {
            PacketData {
                token,
                sender,
                receiver,
                memo,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC transfer message
        pub fn arb_ibc_msg_transfer()(
            port_id_on_a in arb_ibc_port_id(),
            chan_id_on_a in arb_ibc_channel_id(),
            packet_data in arb_ibc_packet_data(),
            timeout_height_on_b in arb_ibc_timeout_data(),
            timeout_timestamp_on_b in arb_ibc_timestamp(),
        ) -> MsgTransfer {
            MsgTransfer {
                port_id_on_a,
                chan_id_on_a,
                packet_data,
                timeout_height_on_b,
                timeout_timestamp_on_b,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC token ID
        pub fn arb_ibc_token_id()(token_id in "[a-zA-Z0-9_]+") -> TokenId {
            TokenId::from_str(&token_id).expect("generated invalid IBC token ID")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC token ID vector
        pub fn arb_ibc_token_ids()(token_ids in collection::hash_set(arb_ibc_token_id().prop_map(|x| x.to_string()), 1..10)) -> TokenIds {
            TokenIds::try_from(token_ids.into_iter().collect::<Vec<_>>()).expect("generated invalid IBC token ID vector")
        }
    }

    prop_compose! {
        /// Generate arbitrary IBC class data
        pub fn arb_ibc_class_data()(class_data in "[a-zA-Z0-9_]*") -> ClassData {
            ClassData::from_str(&class_data).expect("generated invalid IBC class data")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC class ID
        pub fn arb_ibc_class_id()(token_id in "[a-zA-Z0-9_]+") -> ClassId {
            ClassId::from_str(&token_id).expect("generated invalid IBC class ID")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC prefixed class ID
        pub fn arb_ibc_prefixed_class_id()(
            trace_path in arb_ibc_trace_path(),
            base_class_id in arb_ibc_class_id(),
        ) -> PrefixedClassId {
            PrefixedClassId {
                trace_path,
                base_class_id,
            }
        }
    }

    prop_compose! {
        /// Generate arbitrary IBC token data
        pub fn arb_ibc_token_data()(
            token_data in "[a-zA-Z0-9_]*",
        ) -> TokenData {
            TokenData::from_str(&token_data).expect("generated invalid IBC token data")
        }
    }

    // An arbitrary URI for the tests. Generating random URIs would not increase
    // test coverage since they are encoded as length-prefixed strings.
    const ARBITRARY_URI: &str = "https://namada.net/#ibc-interoperability";

    prop_compose! {
        /// Generate arbitrary NFT packet data
        pub fn arb_ibc_nft_packet_data()(
            token_ids in arb_ibc_token_ids(),
            token_uri in Just(TokenUri::from_str(ARBITRARY_URI).unwrap()),
        )(
            sender in arb_ibc_signer(),
            receiver in arb_ibc_signer(),
            memo in option::of(arb_ibc_nft_memo()),
            class_data in option::of(arb_ibc_class_data()),
            class_id in arb_ibc_prefixed_class_id(),
            class_uri in option::of(Just(ClassUri::from_str(ARBITRARY_URI).unwrap())),
            token_uris in option::of(collection::vec(Just(token_uri), token_ids.0.len())),
            token_data in option::of(collection::vec(arb_ibc_token_data(), token_ids.0.len())),
            token_ids in Just(token_ids),
        ) -> NftPacketData {
            NftPacketData {
                token_ids,
                sender,
                receiver,
                memo,
                class_data,
                class_id,
                class_uri,
                token_uris,
                token_data,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC NFT transfer message
        pub fn arb_ibc_msg_nft_transfer()(
            port_id_on_a in arb_ibc_port_id(),
            chan_id_on_a in arb_ibc_channel_id(),
            packet_data in arb_ibc_nft_packet_data(),
            timeout_height_on_b in arb_ibc_timeout_data(),
            timeout_timestamp_on_b in arb_ibc_timestamp(),
        ) -> MsgNftTransfer {
            MsgNftTransfer {
                port_id_on_a,
                chan_id_on_a,
                packet_data,
                timeout_height_on_b,
                timeout_timestamp_on_b,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC any object
        pub fn arb_ibc_any()(any in prop_oneof![
            arb_ibc_msg_transfer().prop_map(|x| x.to_any()),
            arb_ibc_msg_nft_transfer().prop_map(|x| x.to_any()),
        ]) -> Any {
            any
        }
    }
}
