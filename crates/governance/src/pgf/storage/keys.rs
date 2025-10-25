use namada_core::address::Address;
use namada_core::storage::{DbKeySeg, Key, KeySeg};
use namada_macros::StorageKeys;
use namada_state::collections::{LazyCollection, LazyMap, lazy_map};

use crate::pgf::ADDRESS;
use crate::pgf::storage::steward::StewardDetail;
use crate::storage::proposal::ContPGFTarget;

/// Storage keys for pgf internal address.
#[derive(StorageKeys)]
struct Keys {
    stewards: &'static str,
    fundings: &'static str,
    pgf_inflation_rate: &'static str,
    steward_inflation_rate: &'static str,
    maximum_number_of_stewards: &'static str,
}

/// Obtain a storage key for stewards key
pub fn stewards_key_prefix() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS.to_owned()),
            DbKeySeg::StringSeg(Keys::VALUES.stewards.to_string()),
        ],
    }
}

/// LazyMap handler for the stewards subspace
pub fn stewards_handle() -> LazyMap<Address, StewardDetail> {
    LazyMap::open(stewards_key_prefix())
}

/// Check if the given storage key is a steward key. If it is, returns the
/// steward address.
pub fn is_stewards_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(pgf),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(data),
            DbKeySeg::AddressSeg(steward),
        ] if pgf.eq(&ADDRESS)
            && prefix.as_str() == Keys::VALUES.stewards
            && data.as_str() == lazy_map::DATA_SUBKEY =>
        {
            Some(steward)
        }
        _ => None,
    }
}

/// Obtain a storage key for pgf fundings.
pub fn fundings_key_prefix() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS.to_owned()),
            DbKeySeg::StringSeg(Keys::VALUES.fundings.to_string()),
        ],
    }
}

/// Nested LazyMap handler for the continuous PGF substorage. Structure: Address
/// -> Proposal ID -> Target data
pub fn fundings_handle()
-> lazy_map::NestedMap<String, LazyMap<u64, ContPGFTarget>> {
    LazyMap::open(fundings_key_prefix())
}

/// Check if the given storage key is a pgf funding key.
pub fn is_fundings_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(pgf), DbKeySeg::StringSeg(prefix), DbKeySeg::StringSeg(data), DbKeySeg::AddressSeg(_)] if pgf.eq(&ADDRESS)
               && prefix.as_str() == Keys::VALUES.fundings
                && data.as_str() == lazy_map::DATA_SUBKEY)
}

/// Check if key is inside governance address space
pub fn is_pgf_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &ADDRESS)
}

/// Check if key is a pgf inflation rate key
pub fn is_pgf_inflation_rate_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(prefix)] if addr == &ADDRESS && prefix == Keys::VALUES.pgf_inflation_rate)
}

/// Check if key is a steward inflation rate key
pub fn is_steward_inflation_rate_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(prefix)] if addr == &ADDRESS && prefix == Keys::VALUES.steward_inflation_rate)
}

/// Get key for inflation rate key
pub fn get_pgf_inflation_rate_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.pgf_inflation_rate.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key for maximum number of pgf stewards
pub fn get_maximum_number_of_pgf_steward_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.maximum_number_of_stewards.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key for inflation rate key
pub fn get_steward_inflation_rate_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.steward_inflation_rate.to_owned())
        .expect("Cannot obtain a storage key")
}
