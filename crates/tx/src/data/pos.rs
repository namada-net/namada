//! Types used for PoS system transactions

use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::dec::Dec;
use namada_core::key::{common, secp256k1};
use namada_core::token;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

/// A tx data type to become a validator account.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct BecomeValidator {
    /// Address of an account that will become a validator.
    pub address: Address,
    /// A key to be used for signing blocks and votes on blocks.
    pub consensus_key: common::PublicKey,
    /// An Eth bridge governance public key
    pub eth_cold_key: secp256k1::PublicKey,
    /// An Eth bridge hot signing public key used for validator set updates and
    /// cross-chain transactions
    pub eth_hot_key: secp256k1::PublicKey,
    /// Public key used to sign protocol transactions
    pub protocol_key: common::PublicKey,
    /// The initial commission rate charged for delegation rewards
    pub commission_rate: Dec,
    /// The maximum change allowed per epoch to the commission rate. This is
    /// immutable once set here.
    pub max_commission_rate_change: Dec,
    /// The validator email
    pub email: String,
    /// The validator description
    pub description: Option<String>,
    /// The validator website
    pub website: Option<String>,
    /// The validator's discord handle
    pub discord_handle: Option<String>,
    /// URL that points to a picture (e.g. PNG),
    /// identifying the validator
    pub avatar: Option<String>,
    /// Validator's name
    pub name: Option<String>,
}

/// A bond is a validator's self-bond or a delegation from non-validator to a
/// validator.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct Bond {
    /// Validator address
    pub validator: Address,
    /// The amount of tokens
    pub amount: token::Amount,
    /// Source address for delegations. For self-bonds, the validator is
    /// also the source.
    pub source: Option<Address>,
}

/// An unbond of a bond.
pub type Unbond = Bond;

/// A withdrawal of an unbond.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct Withdraw {
    /// Validator address
    pub validator: Address,
    /// Source address for withdrawing from delegations. For withdrawing
    /// from self-bonds, the validator is also the source
    pub source: Option<Address>,
}

/// A claim of pending rewards.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct ClaimRewards {
    /// Validator address
    pub validator: Address,
    /// Source address for claiming rewards from a bond. For self-bonds, the
    /// validator is also the source
    pub source: Option<Address>,
    /// Optional rewards receiver address
    pub receiver: Option<Address>,
}

/// A redelegation of bonded tokens from one validator to another.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct Redelegation {
    /// Source validator address
    pub src_validator: Address,
    /// Destination validator address
    pub dest_validator: Address,
    /// Owner (delegator) of the bonds to be redelegate
    pub owner: Address,
    /// The amount of tokens
    pub amount: token::Amount,
}

/// A change to the validator commission rate.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct CommissionChange {
    /// Validator address
    pub validator: Address,
    /// The new commission rate
    pub new_rate: Dec,
}

/// A change to the validator metadata.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct MetaDataChange {
    /// Validator address
    pub validator: Address,
    /// Validator's email
    pub email: Option<String>,
    /// Validator description
    pub description: Option<String>,
    /// Validator website
    pub website: Option<String>,
    /// Validator's discord handle
    pub discord_handle: Option<String>,
    /// Validator's avatar url
    pub avatar: Option<String>,
    /// Validator's name
    pub name: Option<String>,
    /// Validator's commission rate
    pub commission_rate: Option<Dec>,
}

/// A change to the validator's consensus key.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct ConsensusKeyChange {
    /// Validator address
    pub validator: Address,
    /// The new consensus key
    pub consensus_key: common::PublicKey,
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for proof-of-stake
pub mod tests {
    use namada_core::address::testing::arb_non_internal_address;
    use namada_core::dec::testing::arb_dec;
    use namada_core::key::testing::{arb_common_pk, arb_pk};
    use namada_core::token::testing::arb_amount;
    use proptest::{option, prop_compose};

    use super::*;

    prop_compose! {
        /// Generate a bond
        pub fn arb_bond()(
            validator in arb_non_internal_address(),
            amount in arb_amount(),
            source in option::of(arb_non_internal_address()),
        ) -> Bond {
            Bond {
                validator,
                amount,
                source,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary withdraw
        pub fn arb_withdraw()(
            validator in arb_non_internal_address(),
            source in option::of(arb_non_internal_address()),
        ) -> Withdraw {
            Withdraw {
                validator,
                source,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary commission change
        pub fn arb_commission_change()(
            validator in arb_non_internal_address(),
            new_rate in arb_dec(),
        ) -> CommissionChange {
            CommissionChange {
                validator,
                new_rate,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary metadata change
        pub fn arb_metadata_change()(
            validator in arb_non_internal_address(),
            email in option::of("[a-zA-Z0-9_]*"),
            description in option::of("[a-zA-Z0-9_]*"),
            website in option::of("[a-zA-Z0-9_]*"),
            discord_handle in option::of("[a-zA-Z0-9_]*"),
            avatar in option::of("[a-zA-Z0-9_]*"),
            name in option::of("[a-zA-Z0-9_]*"),
            commission_rate in option::of(arb_dec()),
        ) -> MetaDataChange {
            MetaDataChange {
                validator,
                email,
                description,
                website,
                discord_handle,
                avatar,
                name,
                commission_rate,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary consensus key change
        pub fn arb_consensus_key_change()(
            validator in arb_non_internal_address(),
            consensus_key in arb_common_pk(),
        ) -> ConsensusKeyChange {
            ConsensusKeyChange {
                validator,
                consensus_key,
            }
        }
    }

    prop_compose! {
        /// Generate a validator initialization
        pub fn arb_become_validator()(
            address in arb_non_internal_address(),
            consensus_key in arb_common_pk(),
            eth_cold_key in arb_pk::<secp256k1::SigScheme>(),
            eth_hot_key in arb_pk::<secp256k1::SigScheme>(),
            protocol_key in arb_common_pk(),
            commission_rate in arb_dec(),
            max_commission_rate_change in arb_dec(),
            email in "[a-zA-Z0-9_]*",
            description in option::of("[a-zA-Z0-9_]*"),
            website in option::of("[a-zA-Z0-9_]*"),
            discord_handle in option::of("[a-zA-Z0-9_]*"),
            avatar in option::of("[a-zA-Z0-9_]*"),
            name in option::of("[a-zA-Z0-9_]*"),
        ) -> BecomeValidator {
            BecomeValidator {
                address,
                consensus_key,
                eth_cold_key,
                eth_hot_key,
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                email,
                description,
                website,
                discord_handle,
                avatar,
                name,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary redelegation
        pub fn arb_redelegation()(
            src_validator in arb_non_internal_address(),
            dest_validator in arb_non_internal_address(),
            owner in arb_non_internal_address(),
            amount in arb_amount(),
        ) -> Redelegation {
            Redelegation {
                src_validator,
                dest_validator,
                owner,
                amount,
            }
        }
    }
}
