#![allow(clippy::non_canonical_partial_ord_impl)]
//! The parameters used for the chain's genesis

pub mod chain;
pub mod templates;
pub mod transactions;
pub mod utils;

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use derivative::Derivative;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_sdk::address::{Address, EstablishedAddress};
use namada_sdk::borsh::{BorshDeserialize, BorshSerialize};
use namada_sdk::collections::HashMap;
use namada_sdk::governance::parameters::GovernanceParameters;
use namada_sdk::governance::pgf::parameters::PgfParameters;
use namada_sdk::key::*;
use namada_sdk::parameters::{EpochDuration, ProposalBytes};
use namada_sdk::proof_of_stake::{Dec, GenesisValidator, OwnedPosParams};
use namada_sdk::string_encoding::StringEncoded;
use namada_sdk::time::DateTimeUtc;
use namada_sdk::token::Denomination;
use namada_sdk::{storage, token};
use serde::{Deserialize, Serialize};

#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
)]
pub enum GenesisAddress {
    /// Encoded as `public_key = "value"` in toml.
    PublicKey(StringEncoded<common::PublicKey>),
    /// Encoded as `established_address = "value"` in toml.
    EstablishedAddress(EstablishedAddress),
}

impl GenesisAddress {
    /// Return an [`Address`] from this [`GenesisAddress`].
    #[inline]
    pub fn address(&self) -> Address {
        match self {
            Self::EstablishedAddress(addr) => {
                Address::Established(addr.clone())
            }
            Self::PublicKey(pk) => (&pk.raw).into(),
        }
    }
}

impl Serialize for GenesisAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            GenesisAddress::EstablishedAddress(address) => {
                Serialize::serialize(
                    &Address::Established(address.clone()),
                    serializer,
                )
            }
            GenesisAddress::PublicKey(pk) => {
                Serialize::serialize(pk, serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for GenesisAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FieldVisitor;

        impl serde::de::Visitor<'_> for FieldVisitor {
            type Value = GenesisAddress;

            fn expecting(
                &self,
                formatter: &mut Formatter<'_>,
            ) -> std::fmt::Result {
                formatter.write_str(
                    "a bech32m encoded public key or an established address",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                GenesisAddress::from_str(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(FieldVisitor)
    }
}

impl Display for GenesisAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenesisAddress::EstablishedAddress(address) => {
                write!(f, "{}", Address::Established(address.clone()).encode())
            }
            GenesisAddress::PublicKey(pk) => write!(f, "{}", pk),
        }
    }
}

impl FromStr for GenesisAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // Try to deserialize a PK first
        let maybe_pk = StringEncoded::<common::PublicKey>::from_str(value);
        match maybe_pk {
            Ok(pk) => Ok(GenesisAddress::PublicKey(pk)),
            Err(_) => {
                // If that doesn't work, attempt to retrieve
                // an established address
                let address =
                    Address::from_str(value).map_err(|err| err.to_string())?;
                if let Address::Established(established) = address {
                    Ok(GenesisAddress::EstablishedAddress(established))
                } else {
                    Err("expected an established address or public key"
                        .to_string())
                }
            }
        }
    }
}

#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
)]
#[allow(missing_docs)]
pub enum AddrOrPk {
    PublicKey(StringEncoded<common::PublicKey>),
    Address(Address),
}

impl AddrOrPk {
    /// Return an [`Address`] from this [`AddrOrPk`].
    #[inline]
    pub fn address(&self) -> Address {
        match self {
            Self::Address(addr) => addr.clone(),
            Self::PublicKey(pk) => (&pk.raw).into(),
        }
    }
}

impl Serialize for AddrOrPk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            AddrOrPk::Address(address) => {
                Serialize::serialize(&address, serializer)
            }
            AddrOrPk::PublicKey(pk) => Serialize::serialize(pk, serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AddrOrPk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FieldVisitor;

        impl serde::de::Visitor<'_> for FieldVisitor {
            type Value = AddrOrPk;

            fn expecting(
                &self,
                formatter: &mut Formatter<'_>,
            ) -> std::fmt::Result {
                formatter
                    .write_str("a bech32m encoded public key or an address")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                AddrOrPk::from_str(value).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(FieldVisitor)
    }
}

impl Display for AddrOrPk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddrOrPk::Address(address) => write!(f, "{address}"),
            AddrOrPk::PublicKey(pk) => write!(f, "{}", pk),
        }
    }
}

impl FromStr for AddrOrPk {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // Try to deserialize a PK first
        let maybe_pk = StringEncoded::<common::PublicKey>::from_str(value);
        match maybe_pk {
            Ok(pk) => Ok(AddrOrPk::PublicKey(pk)),
            Err(_) => {
                // If that doesn't work, attempt to retrieve
                // an address
                let address =
                    Address::from_str(value).map_err(|err| err.to_string())?;
                Ok(AddrOrPk::Address(address))
            }
        }
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
#[borsh(init=init)]
pub struct Genesis {
    pub genesis_time: DateTimeUtc,
    pub native_token: Address,
    pub validators: Vec<Validator>,
    pub token_accounts: Vec<TokenAccount>,
    pub established_accounts: Vec<EstablishedAccount>,
    pub implicit_accounts: Vec<ImplicitAccount>,
    pub parameters: Parameters,
    pub pos_params: OwnedPosParams,
    pub gov_params: GovernanceParameters,
    pub pgf_params: PgfParameters,
}

impl Genesis {
    /// Sort all fields for deterministic encoding
    pub fn init(&mut self) {
        self.validators.sort();
        self.token_accounts.sort();
        self.established_accounts.sort();
        self.implicit_accounts.sort();
    }
}

#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
/// Genesis validator definition
pub struct Validator {
    /// Data that is used for PoS system initialization
    pub pos_data: GenesisValidator,
    /// Public key associated with the validator account. The default validator
    /// VP will check authorization of transactions from this account against
    /// this key on a transaction signature.
    /// Note that this is distinct from consensus key used in the PoS system.
    pub account_key: common::PublicKey,
    /// These tokens are not staked and hence do not contribute to the
    /// validator's voting power
    pub non_staked_balance: token::Amount,
    /// Validity predicate code WASM
    pub validator_vp_code_path: String,
    /// Expected SHA-256 hash of the validator VP
    pub validator_vp_sha256: [u8; 32],
}

#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    Derivative,
)]
#[derivative(PartialOrd, Ord)]
pub struct EstablishedAccount {
    /// Address
    pub address: Address,
    /// Validity predicate code WASM
    pub vp_code_path: String,
    /// Expected SHA-256 hash of the validity predicate wasm
    pub vp_sha256: [u8; 32],
    /// A public key to be stored in the account's storage, if any
    pub public_key: Option<common::PublicKey>,
    /// Account's sub-space storage. The values must be borsh encoded bytes.
    #[derivative(PartialOrd = "ignore", Ord = "ignore")]
    pub storage: HashMap<storage::Key, Vec<u8>>,
}

#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    Derivative,
)]
#[derivative(PartialOrd, Ord)]
pub struct TokenAccount {
    /// Address
    pub address: Address,
    /// The number of decimal places amounts of this token has
    pub denom: Denomination,
    /// Accounts' balances of this token
    #[derivative(PartialOrd = "ignore", Ord = "ignore")]
    pub balances: HashMap<Address, token::Amount>,
    /// Token parameters
    pub masp_params: Option<token::ShieldedParams>,
    /// Token inflation from the last epoch (read + write for every epoch)
    pub last_inflation: token::Amount,
    /// Token shielded ratio from the last epoch (read + write for every epoch)
    pub last_locked_ratio: Dec,
}

#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct ImplicitAccount {
    /// A public key from which the implicit account is derived. This will be
    /// stored on chain for the account.
    pub public_key: common::PublicKey,
}

/// Protocol parameters.
///
/// This is almost the same as [`crate::parameters::Parameters`], but instead of
/// having the `implicit_vp` WASM code bytes, it only has the name and sha as
/// the actual code is loaded on `init_chain`
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct Parameters {
    /// Max payload size, in bytes, for a tx batch proposal.
    pub max_proposal_bytes: ProposalBytes,
    /// Max block gas
    pub max_block_gas: u64,
    /// Epoch duration
    pub epoch_duration: EpochDuration,
    /// Allowed validity predicate hashes
    pub vp_allowlist: Vec<String>,
    /// Allowed tx hashes
    pub tx_allowlist: Vec<String>,
    /// Implicit accounts validity predicate code WASM
    pub implicit_vp_code_path: String,
    /// Expected SHA-256 hash of the implicit VP
    pub implicit_vp_sha256: [u8; 32],
    /// Expected number of epochs per year (read only)
    pub epochs_per_year: u64,
    /// How many epochs it takes to transition to the next masp epoch
    pub masp_epoch_multiplier: u64,
    /// The gas limit for a masp transaction paying fees
    pub masp_fee_payment_gas_limit: u64,
    /// Gas scale
    pub gas_scale: u64,
    /// Map of the cost per gas unit for every token allowed for fee payment
    pub minimum_gas_price: BTreeMap<Address, token::Amount>,
}

/// Modify the default genesis file (namada/genesis/localnet/) to
/// accommodate testing.
///
/// This includes adding a specified number of validators.
#[allow(clippy::arithmetic_side_effects)]
#[cfg(any(test, feature = "benches", feature = "testing"))]
pub fn make_dev_genesis(
    num_validators: u64,
    target_chain_dir: &std::path::Path,
) -> crate::config::genesis::chain::Finalized {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use namada_sdk::chain::ChainIdPrefix;
    use namada_sdk::key::*;
    use namada_sdk::proof_of_stake::types::ValidatorMetaData;
    use namada_sdk::tx::standalone_signature;
    use namada_sdk::wallet::alias::Alias;

    use crate::config::genesis::chain::{
        DeriveEstablishedAddress, FinalizedEstablishedAccountTx, finalize,
    };
    use crate::wallet::defaults;

    let mut current_path = std::env::current_dir()
        .expect("Current directory should exist")
        .canonicalize()
        .expect("Current directory should exist");
    // Find the project root dir
    while !current_path.join("rust-toolchain.toml").exists() {
        current_path.pop();
    }
    let chain_dir = current_path.join("genesis").join("localnet");
    let templates = templates::load_and_validate(&chain_dir)
        .expect("Missing genesis files");
    let mut genesis = finalize(
        templates,
        ChainIdPrefix::from_str("test").unwrap(),
        #[allow(clippy::disallowed_methods)]
        DateTimeUtc::now(),
        Duration::from_secs(30).into(),
    );

    // Use the default token address for matching tokens
    let default_tokens: HashMap<Alias, Address> = defaults::tokens()
        .into_iter()
        .map(|(address, alias)| (Alias::from(alias), address))
        .collect();
    for (alias, token) in genesis.tokens.token.iter_mut() {
        if let Some(addr) = default_tokens.get(alias) {
            token.address = addr.clone();
        }
    }

    let assert_established_addr = |addr: &Address| {
        if let Address::Established(addr) = addr {
            addr.clone()
        } else {
            panic!("should have gotten an established address")
        }
    };

    // remove Albert's bond since it messes up existing unit test math
    if let Some(bonds) = genesis.transactions.bond.as_mut() {
        let default_addresses: HashMap<Alias, Address> =
            defaults::addresses().into_iter().collect();
        let fat_alberts_address =
            GenesisAddress::EstablishedAddress(assert_established_addr(
                default_addresses
                    .get(&Alias::from_str("albert").unwrap())
                    .unwrap(),
            ));
        bonds.retain(|bond| bond.source != fat_alberts_address);
    };
    // fetch validator's balances
    let (first_val_balance, first_val_bonded) = {
        let nam_balances = genesis
            .balances
            .token
            .get_mut(&Alias::from_str("nam").unwrap())
            .unwrap();

        let tx = genesis
            .transactions
            .validator_account
            .as_ref()
            .unwrap()
            .first()
            .unwrap();
        let genesis_addr = Address::Established(tx.tx.data.address.raw.clone());

        let balance = *nam_balances.0.get(&genesis_addr).unwrap();
        let bonded = {
            let bond =
                genesis.transactions.bond.as_mut().unwrap().first().unwrap();
            bond.amount
        };

        (balance, bonded)
    };
    let secp_eth_cold_keypair = secp256k1::SecretKey::try_from_slice(&[
        90, 83, 107, 155, 193, 251, 120, 27, 76, 1, 188, 8, 116, 121, 90, 99,
        65, 17, 187, 6, 238, 141, 63, 188, 76, 38, 102, 7, 47, 185, 28, 52,
    ])
    .unwrap();
    let sign_pk = |sk: &common::SecretKey| transactions::SignedPk {
        pk: StringEncoded { raw: sk.ref_to() },
        authorization: StringEncoded {
            raw: standalone_signature::<_, SerializeWithBorsh>(
                sk,
                &sk.ref_to(),
            ),
        },
    };
    // Add other validators with randomly generated keys if needed
    for _val in 0..(num_validators - 1) {
        let consensus_keypair: common::SecretKey =
            testing::gen_keypair::<ed25519::SigScheme>()
                .try_to_sk()
                .unwrap();
        let eth_cold_keypair =
            common::SecretKey::try_from_sk(&secp_eth_cold_keypair).unwrap();
        let (protocol_keypair, eth_bridge_keypair) = defaults::validator_keys();
        // add the validator
        let validator_address = {
            let vals = genesis.transactions.validator_account.as_mut().unwrap();
            let established_accounts =
                genesis.transactions.established_account.as_mut().unwrap();

            let tx = transactions::EstablishedAccountTx {
                vp: utils::VP_USER.to_string(),
                public_keys: vec![StringEncoded::new(
                    consensus_keypair.ref_to(),
                )],
                threshold: 1,
            };
            let address = tx.derive_established_address();
            let established_account_tx = FinalizedEstablishedAccountTx {
                address: Address::Established(address.clone()),
                tx,
            };
            established_accounts.push(established_account_tx);

            let validator_account_tx = transactions::ValidatorAccountTx {
                address: StringEncoded::new(address.clone()),
                vp: utils::VP_USER.to_string(),
                commission_rate: Dec::new(5, 2).expect("This can't fail"),
                max_commission_rate_change: Dec::new(1, 2)
                    .expect("This can't fail"),
                metadata: ValidatorMetaData {
                    email: "null@null.net".to_string(),
                    description: None,
                    website: None,
                    discord_handle: None,
                    avatar: None,
                    name: None,
                },
                net_address: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    8080,
                ),
                consensus_key: StringEncoded {
                    raw: consensus_keypair.to_public(),
                },
                protocol_key: StringEncoded {
                    raw: protocol_keypair.to_public(),
                },
                tendermint_node_key: StringEncoded {
                    raw: consensus_keypair.to_public(),
                },
                eth_hot_key: StringEncoded {
                    raw: eth_bridge_keypair.to_public(),
                },
                eth_cold_key: StringEncoded {
                    raw: eth_cold_keypair.to_public(),
                },
            };
            vals.push(chain::FinalizedValidatorAccountTx {
                tx: transactions::Signed::new(
                    transactions::ValidatorAccountTx {
                        address: StringEncoded::new(address.clone()),
                        vp: validator_account_tx.vp,
                        commission_rate: validator_account_tx.commission_rate,
                        max_commission_rate_change: validator_account_tx
                            .max_commission_rate_change,
                        metadata: validator_account_tx.metadata,
                        net_address: validator_account_tx.net_address,
                        consensus_key: sign_pk(&consensus_keypair),
                        protocol_key: sign_pk(&protocol_keypair),
                        tendermint_node_key: sign_pk(&consensus_keypair),
                        eth_hot_key: sign_pk(&eth_bridge_keypair),
                        eth_cold_key: sign_pk(&eth_cold_keypair),
                    },
                ),
            });
            address
        };
        // credit nam tokens to validators such that they can bond
        {
            let nam_balances = genesis
                .balances
                .token
                .get_mut(&Alias::from_str("nam").unwrap())
                .unwrap();

            let validator_addr: Address =
                Address::Established(validator_address.clone());
            let account_pk: Address = (&consensus_keypair.ref_to()).into();

            nam_balances.0.insert(validator_addr, first_val_balance);
            nam_balances.0.insert(account_pk, first_val_balance);
        }
        // self bond
        if let Some(bonds) = genesis.transactions.bond.as_mut() {
            bonds.push(transactions::BondTx {
                source: GenesisAddress::EstablishedAddress(
                    validator_address.clone(),
                ),
                validator: Address::Established(validator_address),
                amount: first_val_bonded,
            })
        }
    }

    // Write out the TOML files for benches
    #[cfg(feature = "benches")]
    genesis
        .write_toml_files(target_chain_dir)
        .expect("Must be able to write the finalized genesis");
    #[cfg(not(feature = "benches"))]
    let _ = target_chain_dir; // avoid unused warn

    genesis
}

#[cfg(test)]
pub mod tests {
    use namada_sdk::address::testing::gen_established_address;
    use namada_sdk::borsh::BorshSerializeExt;
    use namada_sdk::key::*;
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    use crate::wallet;

    /// Run `cargo test gen_genesis_validator -- --nocapture` to generate a
    /// new genesis validator address and keypair.
    #[test]
    fn gen_genesis_validator() {
        let address = gen_established_address();
        let mut rng: ThreadRng = thread_rng();
        let keypair: common::SecretKey =
            ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap();
        let kp_arr = keypair.serialize_to_vec();
        let (protocol_keypair, _eth_hot_bridge_keypair) =
            wallet::defaults::validator_keys();

        let eth_cold_gov_keypair: common::SecretKey =
            secp256k1::SigScheme::generate(&mut rng)
                .try_to_sk()
                .unwrap();
        let eth_hot_bridge_keypair: common::SecretKey =
            secp256k1::SigScheme::generate(&mut rng)
                .try_to_sk()
                .unwrap();

        println!("address: {}", address);
        println!("keypair: {:?}", kp_arr);
        println!("protocol_keypair: {:?}", protocol_keypair);
        println!(
            "eth_cold_gov_keypair: {:?}",
            eth_cold_gov_keypair.serialize_to_vec()
        );
        println!(
            "eth_hot_bridge_keypair: {:?}",
            eth_hot_bridge_keypair.serialize_to_vec()
        );
    }
}
