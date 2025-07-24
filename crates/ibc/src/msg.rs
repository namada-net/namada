use std::collections::BTreeMap;

use borsh::schema::{Declaration, Definition, Fields};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ibc::apps::nft_transfer::types::PORT_ID_STR as NFT_PORT_ID_STR;
use ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use ibc::apps::transfer::types::PORT_ID_STR as FT_PORT_ID_STR;
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use ibc::apps::transfer::types::packet::PacketData;
use ibc::core::channel::types::msgs::{
    MsgRecvPacket as IbcMsgRecvPacket, PacketMsg,
};
use ibc::core::channel::types::packet::Packet;
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::core::host::types::identifiers::PortId;
use ibc::primitives::proto::Protobuf;
use serde::{Deserialize, Serialize};
use namada_core::string_encoding::StringEncoded;
use namada_systems::ibc::IbcShieldingData;
use crate::trace;

trait Sealed {}

/// Marker trait that denotes whether an IBC memo is valid
/// in Namada.
#[allow(private_bounds)]
pub trait ValidNamadaMemo: Sealed {}

impl Sealed for NamadaMemo<NamadaMemoData> {}
impl ValidNamadaMemo for NamadaMemo<NamadaMemoData> {}

impl Sealed for NamadaMemo<OsmosisSwapMemoData> {}
impl ValidNamadaMemo for NamadaMemo<OsmosisSwapMemoData> {}

/// Osmosis swap memo data.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OsmosisSwapMemoData {
    /// The inner memo data.
    pub osmosis_swap: OsmosisSwapMemoDataInner,
}

/// Osmosis swap inner memo data.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OsmosisSwapMemoDataInner {
    /// Shielding transfer data. Hex encodes the borsh serialized MASP
    /// transfer.
    pub shielding_data: StringEncoded<IbcShieldingData>,
    /// The amount that is shielded onto the MASP. Corresponds to the
    /// minimum output amount from the swap.
    pub shielded_amount: namada_core::token::Amount,
    /// The receiver of the difference between the transferred tokens and
    /// the minimum output amount.
    pub overflow_receiver: namada_core::address::Address,
}

impl From<NamadaMemo<OsmosisSwapMemoData>> for NamadaMemo<NamadaMemoData> {
    fn from(memo: NamadaMemo<OsmosisSwapMemoData>) -> Self {
        memo.namada.into()
    }
}

impl From<OsmosisSwapMemoData> for NamadaMemo<NamadaMemoData> {
    fn from(
        OsmosisSwapMemoData {
            osmosis_swap:
                OsmosisSwapMemoDataInner {
                    shielding_data,
                    shielded_amount,
                    overflow_receiver,
                },
        }: OsmosisSwapMemoData,
    ) -> Self {
        Self {
            namada: NamadaMemoData::OsmosisSwap {
                overflow_receiver,
                shielded_amount,
                shielding_data,
            },
        }
    }
}

impl From<OsmosisSwapMemoData> for NamadaMemo<OsmosisSwapMemoData> {
    fn from(data: OsmosisSwapMemoData) -> Self {
        Self { namada: data }
    }
}

/// Memo data serialized as a JSON object included
/// in IBC packets.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NamadaMemo<Data = NamadaMemoData> {
    /// The inner memo data.
    pub namada: Data,
}

/// Data included in a Namada memo.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // TODO Box OsmosisSwap shielding_data
pub enum NamadaMemoData {
    /// Generic message sent over IBC.
    Memo(String),
    /// Osmosis swap message.
    OsmosisSwap {
        /// Shielding transfer data. Hex encodes the borsh serialized MASP
        /// transfer.
        shielding_data: StringEncoded<IbcShieldingData>,
        /// The amount that is shielded onto the MASP. Corresponds to the
        /// minimum output amount from the swap.
        shielded_amount: namada_core::token::Amount,
        /// The receiver of the difference between the transferred tokens and
        /// the minimum output amount.
        overflow_receiver: namada_core::address::Address,
    },
}

/// The different variants of an Ibc message
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // TODO Box MsgNftTransfer
pub enum IbcMessage<Transfer> {
    /// Ibc Envelop
    Envelope(Box<MsgEnvelope>),
    /// Ibc transaprent transfer
    Transfer(Box<MsgTransfer<Transfer>>),
    /// NFT transfer
    NftTransfer(MsgNftTransfer<Transfer>),
}

/// IBC transfer message with `Transfer`
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone)]
pub struct MsgTransfer<Transfer> {
    /// IBC transfer message
    pub message: IbcMsgTransfer,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<Transfer>,
}

impl<Transfer: BorshSerialize> BorshSerialize for MsgTransfer<Transfer> {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (encoded_msg, &self.transfer);
        BorshSerialize::serialize(&members, writer)
    }
}

impl<Transfer: BorshDeserialize> BorshDeserialize for MsgTransfer<Transfer> {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer): (Vec<u8>, Option<Transfer>) =
            BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgTransfer::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self { message, transfer })
    }
}

impl<Transfer: BorshSchema> BorshSchema for MsgTransfer<Transfer> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        <(Vec<u8>, Option<Transfer>)>::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![
            <(Vec<u8>, Option<Transfer>)>::declaration(),
        ]);
        definitions.insert(Self::declaration(), Definition::Struct { fields });
    }

    fn declaration() -> Declaration {
        "MsgTransfer".into()
    }
}

/// IBC NFT transfer message with `Transfer`
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone)]
pub struct MsgNftTransfer<Transfer> {
    /// IBC NFT transfer message
    pub message: IbcMsgNftTransfer,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<Transfer>,
}

impl<Transfer: BorshSerialize> BorshSerialize for MsgNftTransfer<Transfer> {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (encoded_msg, &self.transfer);
        BorshSerialize::serialize(&members, writer)
    }
}

impl<Transfer: BorshDeserialize> BorshDeserialize for MsgNftTransfer<Transfer> {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer): (Vec<u8>, Option<Transfer>) =
            BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgNftTransfer::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self { message, transfer })
    }
}

impl<Transfer: BorshSchema> BorshSchema for MsgNftTransfer<Transfer> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        <(Vec<u8>, Option<Transfer>)>::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![
            <(Vec<u8>, Option<Transfer>)>::declaration(),
        ]);
        definitions.insert(Self::declaration(), Definition::Struct { fields });
    }

    fn declaration() -> Declaration {
        "MsgNftTransfer".into()
    }
}


/// Extract MASP transaction from IBC envelope
pub fn extract_masp_tx_from_envelope(
    envelope: &MsgEnvelope,
) -> Option<IbcShieldingData> {
    match envelope {
        MsgEnvelope::Packet(PacketMsg::Recv(msg)) => {
            extract_masp_tx_from_packet(&msg.packet)
        }
        _ => None,
    }
}

/// Decode IBC shielding data from the string
pub fn decode_ibc_shielding_data(
    s: impl AsRef<str>,
) -> Option<IbcShieldingData> {
    let sref = s.as_ref();

    serde_json::from_str(sref).map_or_else(
        |_| sref.parse().ok(),
        |NamadaMemo { namada: memo_data }| match memo_data {
            NamadaMemoData::Memo(memo) => memo.parse().ok(),
            NamadaMemoData::OsmosisSwap { shielding_data, .. } => {
                Some(shielding_data.raw)
            }
        },
    )
}

/// Extract MASP transaction from IBC packet memo
pub fn extract_masp_tx_from_packet(
    packet: &Packet,
) -> Option<IbcShieldingData> {
    let memo = extract_memo_from_packet(packet, &packet.port_id_on_b)?;
    decode_ibc_shielding_data(memo)
}

fn extract_memo_from_packet(
    packet: &Packet,
    port_id: &PortId,
) -> Option<String> {
    match port_id.as_str() {
        FT_PORT_ID_STR => {
            let packet_data =
                serde_json::from_slice::<PacketData>(&packet.data).ok()?;
            if packet_data.memo.as_ref().is_empty() {
                None
            } else {
                Some(packet_data.memo.as_ref().to_string())
            }
        }
        NFT_PORT_ID_STR => {
            let packet_data =
                serde_json::from_slice::<NftPacketData>(&packet.data).ok()?;
            Some(packet_data.memo?.as_ref().to_string())
        }
        _ => {
            tracing::warn!(
                "Memo couldn't be extracted from the unsupported IBC packet \
                 data for Port ID {port_id}"
            );
            None
        }
    }
}

/// Extract the traces used in a receive packet message
pub fn extract_traces_from_recv_msg(
    msg: &IbcMsgRecvPacket,
) -> Result<Vec<String>, serde_json::Error> {
    match msg.packet.port_id_on_b.as_str() {
        FT_PORT_ID_STR => {
            // Record the token credited/debited in this
            // transfer
            let packet_data =
                serde_json::from_slice::<PacketData>(&msg.packet.data)?;
            let ibc_denom = packet_data.token.denom.to_string();
            Ok([ibc_denom].into())
        }
        NFT_PORT_ID_STR => {
            // Record the tokens credited/debited in this NFT
            // transfer
            let packet_data =
                serde_json::from_slice::<NftPacketData>(&msg.packet.data)?;
            let ibc_traces: Vec<_> = packet_data
                .token_ids
                .0
                .iter()
                .map(|token_id| {
                    trace::ibc_trace_for_nft(&packet_data.class_id, token_id)
                })
                .collect();
            Ok(ibc_traces)
        }
        _ => Ok(vec![]),
    }
}
