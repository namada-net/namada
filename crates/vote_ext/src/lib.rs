//! This module contains types necessary for processing vote extensions.

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

pub mod bridge_pool_roots;
pub mod ethereum_events;
pub mod validator_set_update;

use namada_core::borsh::{
    BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
};
use namada_core::chain::ChainId;
use namada_core::key::common;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_tx::data::TxType;
use namada_tx::data::protocol::{ProtocolTx, ProtocolTxType};
use namada_tx::{Authorization, Signed, Tx, TxError};

/// This type represents the data we pass to the extension of
/// a vote at the PreCommit phase of Tendermint.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct VoteExtension {
    /// Vote extension data related with Ethereum events.
    pub ethereum_events: Option<Signed<ethereum_events::Vext>>,
    /// A signature of the Ethereum bridge pool root and nonce.
    pub bridge_pool_root: Option<bridge_pool_roots::SignedVext>,
    /// Vote extension data related with validator set updates.
    pub validator_set_update: Option<validator_set_update::SignedVext>,
}

/// The consensus version of the node that crafted a protocol
/// transaction, as declared in the `CONSENSUS_VERSION` file and made
/// available by `namada_core::consensus_version`. Nodes running
/// different consensus versions must not agree on the same blocks.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct ConsensusVersion(pub u64);

macro_rules! protocol_tx_data_deserialize_inner {
    ($variant:ty) => {
        impl TryFrom<&Tx> for $variant {
            type Error = TxError;

            fn try_from(tx: &Tx) -> Result<Self, TxError> {
                let tx_data = tx
                    .data(tx.commitments().first().ok_or_else(|| {
                        TxError::Deserialization(
                            "Missing inner protocol tx commitments".into(),
                        )
                    })?)
                    .ok_or_else(|| {
                        TxError::Deserialization(
                            "Expected protocol tx type associated data".into(),
                        )
                    })?;
                Self::try_from_slice(&tx_data)
                    .map_err(|err| TxError::Deserialization(err.to_string()))
            }
        }
    };
}

macro_rules! protocol_tx_data_declare {
        (
            $( #[$outer_attrs:meta] )*
            {
                $(
                    $(#[$inner_attrs:meta])*
                    $variant:ident ($inner_ty:ty)
                ),* $(,)?
            }
        ) => {
            $( #[$outer_attrs] )*
            pub enum ProtocolTxData {
                $(
                    $(#[$inner_attrs])*
                    $variant ( $inner_ty )
                ),*
            }

            /// All the variants of [`ProtocolTxData`], stored
            /// in a trait.
            #[allow(missing_docs)]
            pub trait ProtocolTxDataVariants {
                $( type $variant; )*
            }

            impl ProtocolTxDataVariants for ProtocolTxData {
                $( type $variant = $inner_ty; )*
            }

            #[allow(missing_docs)]
            pub mod protocol_tx_data_variants {
                //! All the variants of [`ProtocolTxData`], stored
                //! in a module.
                use super::*;

                $( pub type $variant = $inner_ty; )*
            }

            $( protocol_tx_data_deserialize_inner!($inner_ty); )*
        };
    }

protocol_tx_data_declare! {
    /// Data associated with Ethereum protocol transactions.
    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer, BorshSchema)]
    {
        /// Ethereum events contained in vote extensions that
        /// are compressed before being included on chain
        EthereumEvents(ethereum_events::VextDigest),
        /// Collection of signatures over the Ethereum bridge
        /// pool merkle root and nonce.
        BridgePool(bridge_pool_roots::MultiSignedVext),
        /// Validator set updates contained in vote extensions
        ValidatorSetUpdate(validator_set_update::VextDigest),
        /// Ethereum events seen by some validator
        EthEventsVext(ethereum_events::SignedVext),
        /// Signature over the Ethereum bridge pool merkle root and nonce.
        BridgePoolVext(bridge_pool_roots::SignedVext),
        /// Validator set update signed by some validator
        ValSetUpdateVext(validator_set_update::SignedVext),
        /// Software version of the node that proposed the block
        ConsensusVersionMarker(ConsensusVersion),
    }
}

impl TryFrom<&Tx> for ProtocolTxData {
    type Error = TxError;

    fn try_from(tx: &Tx) -> Result<Self, TxError> {
        let TxType::Protocol(protocol_tx) = tx.header().tx_type else {
            return Err(TxError::Deserialization(
                "Expected protocol tx type".into(),
            ));
        };
        let Some(tx_data) =
            tx.data(tx.commitments().first().ok_or_else(|| {
                TxError::Deserialization(
                    "Missing inner protocol tx commitments".into(),
                )
            })?)
        else {
            return Err(TxError::Deserialization(
                "Expected protocol tx type associated data".into(),
            ));
        };
        Self::deserialize(&protocol_tx.tx, &tx_data)
    }
}

impl ProtocolTxData {
    /// Sign transaction Ethereum data and wrap it in a [`Tx`].
    pub fn sign(
        &self,
        signing_key: &common::SecretKey,
        chain_id: ChainId,
    ) -> Tx {
        let (tx_data, tx_type) = self.serialize();
        let mut outer_tx =
            Tx::from_type(TxType::Protocol(Box::new(ProtocolTx {
                pk: signing_key.to_public(),
                tx: tx_type,
            })));
        outer_tx.header.chain_id = chain_id;
        outer_tx.set_data(namada_tx::Data::new(tx_data));
        outer_tx.add_section(namada_tx::Section::Authorization(
            Authorization::new(
                outer_tx.sechashes(),
                [(0, signing_key.clone())].into_iter().collect(),
                None,
            ),
        ));
        outer_tx
    }

    /// Serialize Ethereum protocol transaction data.
    pub fn serialize(&self) -> (Vec<u8>, ProtocolTxType) {
        macro_rules! match_of_type {
                ( $( $type:ident ),* $(,)?) => {
                    match self {
                        $( ProtocolTxData::$type(x) =>
                           (x.serialize_to_vec(), ProtocolTxType::$type)),*
                    }
                }
            }
        match_of_type! {
            EthereumEvents,
            BridgePool,
            ValidatorSetUpdate,
            EthEventsVext,
            BridgePoolVext,
            ValSetUpdateVext,
            ConsensusVersionMarker,
        }
    }

    /// Deserialize Ethereum protocol transaction data.
    pub fn deserialize(
        tx_type: &ProtocolTxType,
        data: &[u8],
    ) -> Result<Self, TxError> {
        let deserialize: fn(&[u8]) -> _ = match tx_type {
            ProtocolTxType::EthereumEvents => |data| {
                BorshDeserialize::try_from_slice(data)
                    .map(ProtocolTxData::EthereumEvents)
            },
            ProtocolTxType::BridgePool => |data| {
                BorshDeserialize::try_from_slice(data)
                    .map(ProtocolTxData::BridgePool)
            },
            ProtocolTxType::ValidatorSetUpdate => |data| {
                BorshDeserialize::try_from_slice(data)
                    .map(ProtocolTxData::ValidatorSetUpdate)
            },
            ProtocolTxType::EthEventsVext => |data| {
                BorshDeserialize::try_from_slice(data)
                    .map(ProtocolTxData::EthEventsVext)
            },
            ProtocolTxType::BridgePoolVext => |data| {
                BorshDeserialize::try_from_slice(data)
                    .map(ProtocolTxData::BridgePoolVext)
            },
            ProtocolTxType::ValSetUpdateVext => |data| {
                BorshDeserialize::try_from_slice(data)
                    .map(ProtocolTxData::ValSetUpdateVext)
            },
            ProtocolTxType::ConsensusVersionMarker => |data| {
                BorshDeserialize::try_from_slice(data)
                    .map(ProtocolTxData::ConsensusVersionMarker)
            },
        };
        deserialize(data)
            .map_err(|err| TxError::Deserialization(err.to_string()))
    }
}
