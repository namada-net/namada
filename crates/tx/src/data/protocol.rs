//! Types for sending and verifying txs
//! used in Namada protocols

use namada_core::borsh::{
    BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
};
use namada_core::key::*;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::TxError;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    PartialEq,
)]
/// Txs sent by validators as part of internal protocols
pub struct ProtocolTx {
    /// we require ProtocolTxs be signed
    pub pk: common::PublicKey,
    /// The type of protocol message being sent
    pub tx: ProtocolTxType,
}

impl ProtocolTx {
    /// Validate the signature of a protocol tx
    pub fn validate_sig(
        &self,
        signed_hash: [u8; 32],
        sig: &common::Signature,
    ) -> Result<(), TxError> {
        common::SigScheme::verify_signature(&self.pk, &signed_hash, sig)
            .map_err(|err| {
                TxError::SigError(format!(
                    "ProtocolTx signature verification failed: {}",
                    err
                ))
            })
    }

    /// Produce a SHA-256 hash of this section
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Copy,
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    PartialEq,
)]
/// Types of protocol messages to be sent
pub enum ProtocolTxType {
    /// Ethereum events contained in vote extensions that
    /// are compressed before being included on chain
    EthereumEvents,
    /// Collection of signatures over the Ethereum bridge
    /// pool merkle root and nonce.
    BridgePool,
    /// Validator set updates contained in vote extensions
    ValidatorSetUpdate,
    /// Ethereum events seen by some validator
    EthEventsVext,
    /// Signature over the Ethereum bridge pool merkle root and nonce.
    BridgePoolVext,
    /// Validator set update signed by some validator
    ValSetUpdateVext,
    /// The software version of the node that proposed a block,
    /// used to check consensus compatibility
    ConsensusVersionMarker,
}

impl ProtocolTxType {
    /// Determine if this [`ProtocolTxType`] is an Ethereum
    /// protocol tx.
    #[inline]
    pub fn is_ethereum(&self) -> bool {
        matches!(
            self,
            Self::EthereumEvents
                | Self::BridgePool
                | Self::ValidatorSetUpdate
                | Self::EthEventsVext
                | Self::BridgePoolVext
                | Self::ValSetUpdateVext
        )
    }
}
