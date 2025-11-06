//! The core Namada types, helpers and re-exported dependencies.

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

pub mod arith;
pub mod borsh;
pub mod bytes;
#[cfg(any(test, feature = "control_flow"))]
pub mod control_flow;
pub mod hints;

pub use either;
pub use masp_primitives;
/// Re-export of tendermint v0.37
pub mod tendermint {
    /// Re-export of tendermint v0.37 ABCI
    pub mod abci {
        pub use tendermint::abci::response::ApplySnapshotChunkResult;
        pub use tendermint::abci::{
            Code, Event, EventAttribute, MethodKind, types,
        };
        pub use tendermint::v0_37::abci::*;
    }
    pub use tendermint::*;
}
/// Re-export of tendermint-proto v0.37
pub mod tendermint_proto {
    pub use tendermint_proto::google; // 💩
    pub use tendermint_proto::v0_37::*;
}

#[allow(missing_docs)]
pub mod collections {
    //! Re-exports of collection types.

    pub mod hash_map {
        pub use indexmap::map::{IndexMap as HashMap, *};
    }

    pub mod hash_set {
        pub use indexmap::set::{IndexSet as HashSet, *};
    }

    pub use hash_map::HashMap;
    pub use hash_set::HashSet;
}

pub mod address;
pub mod booleans;
pub mod chain;
pub mod dec;
pub mod eth_abi;
pub mod eth_bridge_pool;
pub mod ethereum_events;
pub mod ethereum_structs;
pub mod hash;
pub mod ibc;
pub mod internal;
pub mod keccak;
pub mod key;
pub mod masp;
pub mod parameters;
pub mod storage;
pub mod string_encoding;
#[cfg(any(test, feature = "task_env"))]
pub mod task_env;
pub mod time;
pub mod token;
pub mod uint;
pub mod validity_predicate;
pub mod voting_power;

use thiserror::Error;

use crate::borsh::{BorshDeserialize, BorshSerialize, BorshSerializeExt};

// Imports `pub fn consensus_version() -> u64` made by build script
include!(concat!(env!("OUT_DIR"), "/consensus_version.rs"));

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Deserialization error: {0}")]
    DeserializationError(std::io::Error),
}

/// Encode a value with borsh
pub fn encode<T>(value: &T) -> Vec<u8>
where
    T: BorshSerialize,
{
    value.serialize_to_vec()
}

/// Decode a value with borsh
pub fn decode<T>(bytes: impl AsRef<[u8]>) -> Result<T, DecodeError>
where
    T: BorshDeserialize,
{
    T::try_from_slice(bytes.as_ref()).map_err(DecodeError::DeserializationError)
}
