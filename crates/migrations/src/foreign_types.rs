//! The procedure for deriving deserializers for types not defined in Namada
//! is as follows:
//!
//! 1. We derive the [`TypeHash`] on the type here.
//! 2. We derive the deserialization function in `crates::sdk::migrations.rs`

use namada_macros::derive_typehash;

use crate::TypeHash;

derive_typehash!(String);
derive_typehash!(Vec::<u8>);
derive_typehash!(Vec::<String>);
derive_typehash!(u64);
derive_typehash!(u128);
derive_typehash!(Option::<u32>);
#[cfg(feature = "masp")]
derive_typehash!(masp_primitives::convert::AllowedConversion);
