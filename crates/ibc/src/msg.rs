use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use borsh::schema::{Declaration, Definition, Fields};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXUPPER;
use ibc::apps::nft_transfer::types::PORT_ID_STR as NFT_PORT_ID_STR;
use ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use ibc::apps::transfer::types::PORT_ID_STR as FT_PORT_ID_STR;
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use ibc::apps::transfer::types::packet::PacketData;
use ibc::core::channel::types::msgs::{
    MsgRecvPacket as IbcMsgRecvPacket, MsgRecvPacket, PacketMsg,
};
use ibc::core::channel::types::packet::Packet;
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::core::host::types::identifiers::{PortId, Sequence};
use ibc::primitives::Signer;
use ibc::primitives::proto::Protobuf;
use masp_primitives::transaction::Transaction as MaspTransaction;
use namada_core::address::Address;
use namada_core::arith::One;
use namada_core::borsh::BorshSerializeExt;
use namada_core::masp::{AssetData, PaymentAddress, ShieldedData};
use namada_core::string_encoding::StringEncoded;
use namada_core::token::{Amount, MaspDigitPos};
use namada_state::StorageRead;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::Digest;

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
    pub shielding_data: StringEncoded<IbcMemoData>,
    /// The amount that is shielded onto the MASP. Corresponds to the
    /// minimum output amount from the swap.
    pub shielded_amount: namada_core::token::Amount,
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
                },
        }: OsmosisSwapMemoData,
    ) -> Self {
        Self {
            namada: NamadaMemoData::OsmosisSwap {
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
        shielding_data: StringEncoded<IbcMemoData>,
        /// The amount that is shielded onto the MASP. Corresponds to the
        /// minimum output amount from the swap.
        shielded_amount: namada_core::token::Amount,
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

/// The memo inside an IBC packet
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct IbcMemoData(pub MaspTransaction);

/// If the shielding data is a payment address,
/// mine a MASP note.
pub fn mine<S, Params, RNG>(
    ctx: &S,
    pa: PaymentAddress,
    tokens: impl IntoIterator<Item = Address>,
    value: Amount,
    mut csprng: &mut RNG,
) -> ShieldedData
where
    S: StorageRead,
    Params: namada_systems::parameters::Read<S>,
    RNG: RngCore + CryptoRng + SeedableRng,
{
    let mut notes = vec![];
    for token in tokens {
        let denom = Params::read_denom(ctx, &token)
            .expect("Failed to read from storage")
            .unwrap_or_default();

        let masp_epoch =
            Params::get_masp_epoch(ctx).expect("Failed to read from storage");
        let asset_data = AssetData {
            token: token.clone(),
            denom,
            position: MaspDigitPos::Zero,
            epoch: Some(masp_epoch),
        };
        let epoch = Params::has_conversions(ctx, &asset_data.encode().unwrap())
            .expect("Could not read from storage")
            .then_some(masp_epoch);
        let mut new_notes = value
            .iter_words()
            .enumerate()
            .filter(|&(_, v)| v > 0)
            .map(|(p, v)| {
                pa.create_note(
                    AssetData {
                        token: token.clone(),
                        denom,
                        position: MaspDigitPos::try_from(
                            u8::try_from(p).unwrap(),
                        )
                        .unwrap(),
                        epoch,
                    }
                    .encode()
                    .unwrap(),
                    v,
                    &mut csprng,
                )
                .unwrap()
            })
            .collect();
        notes.append(&mut new_notes);
    }
    ShieldedData::Note(notes)
}

impl From<&IbcMemoData> for String {
    fn from(data: &IbcMemoData) -> Self {
        HEXUPPER.encode(&data.serialize_to_vec())
    }
}

impl From<IbcMemoData> for String {
    fn from(data: IbcMemoData) -> Self {
        (&data).into()
    }
}

impl fmt::Display for IbcMemoData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from(self))
    }
}

impl FromStr for IbcMemoData {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = HEXUPPER
            .decode(s.as_bytes())
            .map_err(|err| err.to_string())?;
        IbcMemoData::try_from_slice(&bytes).map_err(|err| err.to_string())
    }
}

/// Extract MASP transaction from the memo of an IBC envelope
pub fn extract_masp_tx_from_envelope(
    envelope: &MsgEnvelope,
) -> Option<ShieldedData> {
    match envelope {
        MsgEnvelope::Packet(PacketMsg::Recv(msg)) => {
            let (maybe_memo, _, _) = extract_data_from_packet(
                &msg.packet,
                &msg.packet.port_id_on_b,
            )?;
            if let Some(memo) = maybe_memo {
                if let Some(IbcMemoData(tx)) = decode_ibc_shielding_data(memo) {
                    return Some(ShieldedData::Tx(tx));
                }
            }
            None
        }
        _ => None,
    }
}

/// Decode IBC shielding data from the string
pub fn decode_ibc_shielding_data(s: impl AsRef<str>) -> Option<IbcMemoData> {
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
pub fn extract_shielding_data_from_packet<S, Params, RNG>(
    ctx: &S,
    packet: &Packet,
    tokens: &BTreeSet<Address>,
    csprng: &mut RNG,
) -> Option<ShieldedData>
where
    S: StorageRead,
    Params: namada_systems::parameters::Read<S>,
    RNG: RngCore + CryptoRng + SeedableRng,
{
    let (maybe_memo, receiver, amount) =
        extract_data_from_packet(packet, &packet.port_id_on_b)?;
    if let Some(memo) = maybe_memo {
        if let Some(IbcMemoData(tx)) = decode_ibc_shielding_data(memo) {
            return Some(ShieldedData::Tx(tx));
        }
    }

    let pa = PaymentAddress::from_str(receiver.as_ref()).ok()?;
    Some(mine::<S, Params, RNG>(
        ctx,
        pa,
        tokens.clone(),
        amount,
        csprng,
    ))
}

/// Get the random number generator derived from an IBC packet
/// to mine MASP notes
pub fn extract_rng_from_packet(
    msg: &MsgRecvPacket,
    seq: Sequence,
) -> Result<ChaCha20Rng, String> {
    let csprng = {
        let mut hasher = sha2::Sha256::default();
        hasher.update(msg.packet.port_id_on_b.as_str());
        hasher.update(msg.packet.chan_id_on_b.as_str());
        hasher.update(seq.value().to_le_bytes());
        let seed: [u8; 32] = hasher.finalize().into();
        ChaCha20Rng::from_seed(seed)
    };
    Ok(csprng)
}

/// Get the memo, signer, and amount from an IBC packet
pub fn extract_data_from_packet(
    packet: &Packet,
    port_id: &PortId,
) -> Option<(Option<String>, Signer, Amount)> {
    match port_id.as_str() {
        FT_PORT_ID_STR => {
            let packet_data =
                serde_json::from_slice::<PacketData>(&packet.data).ok()?;
            Some((
                if packet_data.memo.as_ref().is_empty() {
                    None
                } else {
                    Some(packet_data.memo.as_ref().to_string())
                },
                packet_data.receiver,
                packet_data.token.amount.try_into().ok()?,
            ))
        }
        NFT_PORT_ID_STR => {
            let packet_data =
                serde_json::from_slice::<NftPacketData>(&packet.data).ok()?;
            Some((
                packet_data.memo.map(|m| m.as_ref().to_string()),
                packet_data.receiver,
                Amount::one(),
            ))
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

/// Get IBC memo string from MASP transaction for receiving
pub fn convert_masp_tx_to_ibc_memo(transaction: &MaspTransaction) -> String {
    IbcMemoData(transaction.clone()).into()
}
