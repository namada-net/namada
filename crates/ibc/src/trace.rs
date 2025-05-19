//! Functions for IBC token

use std::str::FromStr;

use ibc::apps::nft_transfer::types::{
    PrefixedClassId, TokenId, TracePath as NftTracePath,
};
use ibc::apps::transfer::types::{PrefixedDenom, TracePath};
use ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::address::{Address, HASH_LEN, InternalAddress, SHA_HASH_LEN};
use namada_core::ibc::IbcTokenHash;
use sha2::{Digest, Sha256};

use crate::storage::{Error, Result};

/// Hash the denom
#[inline]
pub fn calc_hash(trace: impl AsRef<str>) -> String {
    calc_ibc_token_hash(trace).to_string()
}

/// Hash the denom
pub fn calc_ibc_token_hash(trace: impl AsRef<str>) -> IbcTokenHash {
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(trace.as_ref());
        hasher.finalize()
    };

    let input: &[u8; SHA_HASH_LEN] = hash.as_ref();
    let mut output = [0; HASH_LEN];

    output.copy_from_slice(&input[..HASH_LEN]);
    IbcTokenHash(output)
}

/// Hash an ICS-20 trace path with one or more hops, returning a string
/// of the form `ibc/<sha256-digest>`.
pub fn calc_ibc_denom(trace: impl AsRef<str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(trace.as_ref());
    let hash = hasher.finalize();
    format!("ibc/{hash:X}")
}

/// Obtain the IbcToken with the hash from the given denom
pub fn ibc_token(trace: impl AsRef<str>) -> Address {
    let hash = calc_ibc_token_hash(&trace);
    Address::Internal(InternalAddress::IbcToken(hash))
}

/// Obtain the IbcToken with the hash from the given NFT class ID and NFT ID
pub fn ibc_token_for_nft(
    class_id: &PrefixedClassId,
    token_id: &TokenId,
) -> Address {
    ibc_token(ibc_trace_for_nft(class_id, token_id))
}

/// Obtain the IBC trace from the given NFT class ID and NFT ID
pub fn ibc_trace_for_nft(
    class_id: &PrefixedClassId,
    token_id: &TokenId,
) -> String {
    format!("{class_id}/{token_id}")
}

/// Convert the given IBC trace to [`Address`]
pub fn convert_to_address(ibc_trace: impl AsRef<str>) -> Result<Address> {
    if ibc_trace.as_ref().contains('/') {
        // validation
        if is_ibc_denom(&ibc_trace).is_none()
            && is_nft_trace(&ibc_trace).is_none()
        {
            return Err(Error::new_alloc(format!(
                "This is not IBC denom and NFT trace: {}",
                ibc_trace.as_ref()
            )));
        }
        Ok(ibc_token(ibc_trace.as_ref()))
    } else {
        Ok(Address::decode(ibc_trace.as_ref())?)
    }
}

/// Returns the trace path and the token string if the denom is an IBC
/// denom.
pub fn is_ibc_denom(denom: impl AsRef<str>) -> Option<(TracePath, String)> {
    let prefixed_denom = PrefixedDenom::from_str(denom.as_ref()).ok()?;
    let base_denom = prefixed_denom.base_denom.to_string();
    if prefixed_denom.trace_path.is_empty() {
        // The denom is just a token or an NFT trace
        return None;
    }
    // The base token isn't decoded because it could be non Namada token
    Some((prefixed_denom.trace_path, base_denom))
}

/// Returns the trace path and the token string if the trace is an NFT one
pub fn is_nft_trace(
    trace: impl AsRef<str>,
) -> Option<(NftTracePath, String, String)> {
    // The trace should be {port}/{channel}/.../{class_id}/{token_id}
    if let Some((class_id, token_id)) = trace.as_ref().rsplit_once('/') {
        let prefixed_class_id = PrefixedClassId::from_str(class_id).ok()?;
        // The base token isn't decoded because it could be non Namada token
        Some((
            prefixed_class_id.trace_path,
            prefixed_class_id.base_class_id.to_string(),
            token_id.to_string(),
        ))
    } else {
        None
    }
}

/// Returns true if the denomination originally came from the sender chain, and
/// false otherwise.
pub fn is_sender_chain_source(
    trace: impl AsRef<str>,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
) -> bool {
    !is_receiver_chain_source(trace, src_port_id, src_channel_id)
}

/// Returns true if the denomination originally came from the receiving chain,
/// and false otherwise.
pub fn is_receiver_chain_source(
    trace: impl AsRef<str>,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
) -> bool {
    trace
        .as_ref()
        .starts_with(&format!("{src_port_id}/{src_channel_id}"))
}
