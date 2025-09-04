//! Genesis transactions

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Debug;
use std::net::SocketAddr;

use itertools::{Either, Itertools};
use ledger_namada_rs::NamadaApp;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_sdk::account::AccountPublicKeysMap;
use namada_sdk::address::{Address, EstablishedAddress};
use namada_sdk::args::{DeviceTransport, Tx as TxArgs};
use namada_sdk::borsh::{BorshDeserialize, BorshSerialize, BorshSerializeExt};
use namada_sdk::chain::ChainId;
use namada_sdk::collections::HashSet;
use namada_sdk::dec::Dec;
use namada_sdk::key::common::PublicKey;
use namada_sdk::key::{RefTo, SerializeWithBorsh, SigScheme, common, ed25519};
use namada_sdk::proof_of_stake::types::ValidatorMetaData;
use namada_sdk::signing::{SigningTxData, sign_tx};
use namada_sdk::string_encoding::StringEncoded;
use namada_sdk::time::DateTimeUtc;
use namada_sdk::token;
use namada_sdk::token::{DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES};
use namada_sdk::tx::data::{Fee, TxType, pos};
use namada_sdk::tx::{
    Code, Commitment, Data, Section, SignatureIndex, TX_BECOME_VALIDATOR_WASM,
    TX_BOND_WASM, Tx, verify_standalone_sig,
};
use namada_sdk::wallet::Wallet;
use namada_sdk::wallet::alias::Alias;
use namada_sdk::wallet::pre_genesis::ValidatorWallet;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::templates::{DenominatedBalances, Parameters, ValidityPredicates};
use crate::config::genesis::chain::DeriveEstablishedAddress;
use crate::config::genesis::templates::{
    TemplateValidation, Unvalidated, Validated,
};
use crate::config::genesis::{GenesisAddress, utils};
use crate::wallet::{CliWalletUtils, WalletTransport};

/// Dummy chain id used to sign [`Tx`] objects at pre-genesis.
pub const NAMADA_GENESIS_TX_ENV_VAR: &str = "NAMADA_GENESIS_TX_CHAIN_ID";
const NAMADA_GENESIS_TX_CHAIN_ID: &str = "namada-genesis";

/// Helper trait to fetch tx data to sign.
pub trait TxToSign {
    /// Return tx data to sign.
    fn tx_to_sign(&self) -> Tx;

    /// Get public keys that may sign this transaction from a genesis address
    fn get_pks(
        &self,
        accounts: &[EstablishedAccountTx],
    ) -> (HashSet<common::PublicKey>, u8);

    fn get_owner(&self) -> GenesisAddress;
}

/// Get the genesis chain ID from "NAMADA_GENESIS_TX_CHAIN_ID" env var, if set,
/// or the default
pub fn genesis_chain_id() -> ChainId {
    ChainId(
        env::var(NAMADA_GENESIS_TX_ENV_VAR)
            .unwrap_or_else(|_| NAMADA_GENESIS_TX_CHAIN_ID.to_string()),
    )
}

/// Return a dummy set of tx arguments to sign with the
/// hardware wallet.
fn get_tx_args(use_device: bool) -> TxArgs {
    use std::str::FromStr;

    TxArgs {
        dry_run: false,
        dry_run_wrapper: false,
        dump_tx: false,
        dump_wrapper_tx: false,
        output_folder: None,
        force: false,
        broadcast_only: false,
        ledger_address: tendermint_rpc::Url::from_str("http://127.0.0.1:26657")
            .unwrap(),
        initialized_account_alias: None,
        wallet_alias_force: false,
        fee_amount: None,
        wrapper_fee_payer: None,
        fee_token: genesis_fee_token_address(),
        gas_limit: 0.into(),
        expiration: Default::default(),
        chain_id: None,
        signing_keys: vec![],
        tx_reveal_code_path: Default::default(),
        password: None,
        memo: None,
        use_device,
        device_transport: DeviceTransport::default(),
    }
}

/// Timestamp used to sign pre-genesis [`Tx`] objects.
#[inline]
fn pre_genesis_tx_timestamp() -> DateTimeUtc {
    DateTimeUtc::from_unix_timestamp(
        // Mon Jan 01 2001 01:01:01 UTC+0000
        978310861,
    )
    .unwrap()
}

/// Return a ready to sign genesis [`Tx`].
fn get_tx_to_sign(tag: impl AsRef<str>, data: impl BorshSerialize) -> Tx {
    let mut tx = Tx::from_type(TxType::Raw);
    tx.header.chain_id = genesis_chain_id();
    tx.header.timestamp = pre_genesis_tx_timestamp();
    tx.set_code(Code {
        salt: [0; 8],
        code: Commitment::Hash(Default::default()),
        tag: Some(tag.as_ref().to_string()),
    });
    tx.set_data(Data {
        salt: [0; 8],
        data: data.serialize_to_vec(),
    });
    let fee_payer = genesis_fee_payer_pk();
    tx.add_wrapper(
        Fee {
            amount_per_gas_unit: DenominatedAmount::native(0.into()),
            token: genesis_fee_token_address(),
        },
        fee_payer,
        0.into(),
    );
    tx
}

/// Get a dummy public key for a fee payer - there are no fees for genesis tx
#[inline]
fn genesis_fee_payer_pk() -> common::PublicKey {
    common::SecretKey::Ed25519(ed25519::SigScheme::from_bytes([0; 32])).ref_to()
}

/// Dummy genesis fee token address - there are no fees for genesis tx
fn genesis_fee_token_address() -> Address {
    Address::from(&genesis_fee_payer_pk())
}

pub struct GenesisValidatorData {
    pub address: EstablishedAddress,
    pub commission_rate: Dec,
    pub max_commission_rate_change: Dec,
    pub net_address: SocketAddr,
    pub self_bond_amount: token::DenominatedAmount,
    pub email: String,
    pub description: Option<String>,
    pub website: Option<String>,
    pub discord_handle: Option<String>,
    pub avatar: Option<String>,
    pub name: Option<String>,
}

/// Sign all genesis transactions.
///
/// Panics if the given `txs.validator_accounts` is non-empty and
/// `validator_wallet` is `None`.
pub async fn sign_txs(
    txs: UnsignedTransactions,
    wallet: &RwLock<Wallet<CliWalletUtils>>,
    validator_wallet: Option<&ValidatorWallet>,
    use_device: bool,
    device_transport: DeviceTransport,
) -> Transactions<Unvalidated> {
    let UnsignedTransactions {
        established_account,
        validator_account,
        bond,
    } = txs;

    // Sign bond txs
    let bond = if let Some(txs) = bond {
        let mut bonds = vec![];
        for tx in txs {
            bonds.push(
                sign_delegation_bond_tx(
                    tx.into(),
                    wallet,
                    &established_account,
                    use_device,
                    device_transport,
                )
                .await,
            );
        }
        Some(bonds)
    } else {
        None
    };

    // Sign validator account txs
    let validator_account = if let Some(txs) = validator_account {
        let validator_wallet = validator_wallet
            .expect("Validator wallet required to sign validator account txs");
        let tnk = validator_wallet.tendermint_node_key.ref_to();
        let mut filtered_txs = vec![];
        for tx in txs {
            if tx.tendermint_node_key.raw == tnk {
                filtered_txs.push(
                    sign_validator_account_tx(
                        Either::Left((tx, validator_wallet)),
                        wallet,
                        established_account.as_ref().expect(
                            "Established account txs required when signing \
                             validator account txs",
                        ),
                        use_device,
                        device_transport,
                    )
                    .await,
                );
            }
        }
        Some(filtered_txs)
    } else {
        None
    };

    Transactions {
        established_account,
        validator_account,
        bond,
    }
}

/// Parse [`UnsignedTransactions`] from a string.
pub fn parse_unsigned(
    raw: &str,
) -> Result<UnsignedTransactions, toml::de::Error> {
    toml::from_str(raw)
}

/// Create signed [`Transactions`] for an established account.
pub fn init_established_account(
    vp: String,
    public_keys: Vec<StringEncoded<common::PublicKey>>,
    threshold: u8,
) -> (Address, UnsignedTransactions) {
    let unsigned_tx = EstablishedAccountTx {
        vp,
        threshold,
        public_keys,
    };
    let address = unsigned_tx.derive_address();
    let txs = UnsignedTransactions {
        established_account: Some(vec![unsigned_tx]),
        ..Default::default()
    };
    (address, txs)
}

/// Create a [`BondTx`] for a genesis validator.
pub fn init_bond(
    source: GenesisAddress,
    validator: EstablishedAddress,
    bond_amount: token::DenominatedAmount,
) -> UnsignedTransactions {
    let unsigned_tx = BondTx {
        source,
        validator: Address::Established(validator),
        amount: bond_amount,
    };
    UnsignedTransactions {
        bond: Some(vec![unsigned_tx]),
        ..Default::default()
    }
}

/// Create [`UnsignedTransactions`] for a genesis validator.
pub fn init_validator(
    GenesisValidatorData {
        address,
        commission_rate,
        max_commission_rate_change,
        net_address,
        self_bond_amount,
        email,
        description,
        website,
        discord_handle,
        avatar,
        name,
    }: GenesisValidatorData,
    validator_wallet: &ValidatorWallet,
) -> (Address, UnsignedTransactions) {
    let unsigned_validator_account_tx = UnsignedValidatorAccountTx {
        address: StringEncoded::new(address),
        consensus_key: StringEncoded::new(
            validator_wallet.consensus_key.ref_to(),
        ),
        protocol_key: StringEncoded::new(
            validator_wallet
                .store
                .validator_keys
                .protocol_keypair
                .ref_to(),
        ),
        tendermint_node_key: StringEncoded::new(
            validator_wallet.tendermint_node_key.ref_to(),
        ),

        eth_hot_key: StringEncoded::new(validator_wallet.eth_hot_key.ref_to()),
        eth_cold_key: StringEncoded::new(
            validator_wallet.eth_cold_key.ref_to(),
        ),
        // No custom validator VPs yet
        vp: utils::VP_USER.to_string(),
        commission_rate,
        max_commission_rate_change,
        net_address,
        metadata: ValidatorMetaData {
            email,
            description,
            website,
            discord_handle,
            avatar,
            name,
        },
    };
    let unsigned_validator_addr =
        unsigned_validator_account_tx.address.raw.clone();
    let validator_account = Some(vec![unsigned_validator_account_tx]);

    let bond = if self_bond_amount.amount().is_zero() {
        None
    } else {
        let unsigned_bond_tx = BondTx {
            source: GenesisAddress::EstablishedAddress(
                unsigned_validator_addr.clone(),
            ),
            validator: Address::Established(unsigned_validator_addr.clone()),
            amount: self_bond_amount,
        };
        Some(vec![unsigned_bond_tx])
    };

    let address = Address::Established(unsigned_validator_addr);
    let txs = UnsignedTransactions {
        validator_account,
        bond,
        ..Default::default()
    };

    (address, txs)
}

pub async fn sign_validator_account_tx(
    to_sign: Either<
        (UnsignedValidatorAccountTx, &ValidatorWallet),
        SignedValidatorAccountTx,
    >,
    wallet: &RwLock<Wallet<CliWalletUtils>>,
    established_accounts: &[EstablishedAccountTx],
    use_device: bool,
    device_transport: DeviceTransport,
) -> SignedValidatorAccountTx {
    let mut to_sign = match to_sign {
        Either::Right(signed_tx) => signed_tx,
        Either::Left((unsigned_tx, validator_wallet)) => {
            fn sign_key<T: BorshSerialize>(
                tx_data: &T,
                keypair: &common::SecretKey,
            ) -> StringEncoded<common::Signature> {
                StringEncoded::new(namada_sdk::tx::standalone_signature::<
                    T,
                    SerializeWithBorsh,
                >(keypair, tx_data))
            }
            // Sign the tx with every validator key to authorize their usage
            let consensus_key_sig =
                sign_key(&unsigned_tx, &validator_wallet.consensus_key);
            let protocol_key_sig = sign_key(
                &unsigned_tx,
                &validator_wallet.store.validator_keys.protocol_keypair,
            );
            let eth_hot_key_sig =
                sign_key(&unsigned_tx, &validator_wallet.eth_hot_key);
            let eth_cold_key_sig =
                sign_key(&unsigned_tx, &validator_wallet.eth_cold_key);
            let tendermint_node_key_sig =
                sign_key(&unsigned_tx, &validator_wallet.tendermint_node_key);

            let ValidatorAccountTx {
                address,
                consensus_key,
                protocol_key,
                tendermint_node_key,
                vp,
                commission_rate,
                max_commission_rate_change,
                net_address,
                eth_hot_key,
                eth_cold_key,
                metadata,
            } = unsigned_tx;

            let consensus_key = SignedPk {
                pk: consensus_key,
                authorization: consensus_key_sig,
            };
            let protocol_key = SignedPk {
                pk: protocol_key,
                authorization: protocol_key_sig,
            };
            let tendermint_node_key = SignedPk {
                pk: tendermint_node_key,
                authorization: tendermint_node_key_sig,
            };

            let eth_hot_key = SignedPk {
                pk: eth_hot_key,
                authorization: eth_hot_key_sig,
            };

            let eth_cold_key = SignedPk {
                pk: eth_cold_key,
                authorization: eth_cold_key_sig,
            };

            Signed::new(ValidatorAccountTx {
                address,
                consensus_key,
                protocol_key,
                tendermint_node_key,
                vp,
                commission_rate,
                max_commission_rate_change,
                net_address,
                eth_hot_key,
                eth_cold_key,
                metadata,
            })
        }
    };

    to_sign
        .sign(established_accounts, wallet, use_device, device_transport)
        .await;
    to_sign
}

pub async fn sign_delegation_bond_tx(
    mut to_sign: SignedBondTx<Unvalidated>,
    wallet: &RwLock<Wallet<CliWalletUtils>>,
    established_accounts: &Option<Vec<EstablishedAccountTx>>,
    use_device: bool,
    device_transport: DeviceTransport,
) -> SignedBondTx<Unvalidated> {
    let default = vec![];
    let established_accounts =
        established_accounts.as_ref().unwrap_or(&default);
    to_sign
        .sign(established_accounts, wallet, use_device, device_transport)
        .await;
    to_sign
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct Transactions<T: TemplateValidation> {
    pub established_account: Option<Vec<EstablishedAccountTx>>,
    pub validator_account: Option<Vec<SignedValidatorAccountTx>>,
    pub bond: Option<Vec<T::BondTx>>,
}

impl<T: TemplateValidation> Transactions<T> {
    /// Take the union of two sets of transactions
    pub fn merge(&mut self, mut other: Self) {
        self.established_account = self
            .established_account
            .take()
            .map(|mut txs| {
                if let Some(new_txs) = other.established_account.as_mut() {
                    txs.append(new_txs);
                }
                txs
            })
            .or(other.established_account)
            .map(|txs| txs.into_iter().sorted().dedup().collect());
        self.validator_account = self
            .validator_account
            .take()
            .map(|mut txs| {
                if let Some(new_txs) = other.validator_account.as_mut() {
                    txs.append(new_txs);
                }
                txs
            })
            .or(other.validator_account)
            .map(|txs| txs.into_iter().sorted().dedup().collect());
        self.bond = self
            .bond
            .take()
            .map(|mut txs| {
                if let Some(new_txs) = other.bond.as_mut() {
                    txs.append(new_txs);
                }
                txs
            })
            .or(other.bond)
            .map(|txs| txs.into_iter().sorted().dedup().collect());
    }
}

impl<T: TemplateValidation> Default for Transactions<T> {
    fn default() -> Self {
        Self {
            established_account: None,
            validator_account: None,
            bond: None,
        }
    }
}

impl Transactions<Validated> {
    /// Check that there is at least one validator.
    pub fn has_at_least_one_validator(&self) -> bool {
        self.validator_account
            .as_ref()
            .map(|txs| !txs.is_empty())
            .unwrap_or_default()
    }

    /// Check if there is at least one validator with positive Tendermint voting
    /// power. The voting power is converted from `token::Amount` of the
    /// validator's stake using the `tm_votes_per_token` PoS parameter.
    pub fn has_validator_with_positive_voting_power(
        &self,
        votes_per_token: Dec,
    ) -> bool {
        self.bond
            .as_ref()
            .map(|txs| {
                let mut stakes: BTreeMap<&Address, token::Amount> =
                    BTreeMap::new();
                for tx in txs {
                    let entry = stakes.entry(&tx.validator).or_default();
                    *entry = entry
                        .checked_add(tx.amount.amount())
                        .expect("Validator total stake must not overflow");
                }

                stakes.into_values().any(|stake| {
                    let tendermint_voting_power =
                        namada_sdk::proof_of_stake::types::into_tm_voting_power(
                            votes_per_token,
                            stake,
                        );
                    if tendermint_voting_power > 0 {
                        return true;
                    }
                    false
                })
            })
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnsignedTransactions {
    pub established_account: Option<Vec<EstablishedAccountTx>>,
    pub validator_account: Option<Vec<UnsignedValidatorAccountTx>>,
    pub bond: Option<Vec<BondTx<Unvalidated>>>,
}

pub type UnsignedValidatorAccountTx =
    ValidatorAccountTx<StringEncoded<common::PublicKey>>;

pub type SignedValidatorAccountTx = Signed<ValidatorAccountTx<SignedPk>>;

pub type SignedBondTx<T> = Signed<BondTx<T>>;

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct ValidatorAccountTx<PK: Ord> {
    /// The address of the validator.
    pub address: StringEncoded<EstablishedAddress>,
    // TODO(namada#2554): remove the vp field
    pub vp: String,
    /// Commission rate charged on rewards for delegators (bounded inside
    /// 0-1)
    pub commission_rate: Dec,
    /// Maximum change in commission rate permitted per epoch
    pub max_commission_rate_change: Dec,
    /// P2P IP:port
    pub net_address: SocketAddr,
    /// PKs have to come last in TOML to avoid `ValueAfterTable` error
    pub consensus_key: PK,
    pub protocol_key: PK,
    pub tendermint_node_key: PK,
    pub eth_hot_key: PK,
    pub eth_cold_key: PK,
    /// Validator metadata
    pub metadata: ValidatorMetaData,
}

impl TxToSign for ValidatorAccountTx<SignedPk> {
    fn tx_to_sign(&self) -> Tx {
        get_tx_to_sign(
            TX_BECOME_VALIDATOR_WASM,
            pos::BecomeValidator {
                address: Address::Established(self.address.raw.clone()),
                consensus_key: self.consensus_key.pk.raw.clone(),
                eth_hot_key: match &self.eth_hot_key.pk.raw {
                    common::PublicKey::Secp256k1(key) => key.clone(),
                    _ => unreachable!(),
                },
                eth_cold_key: match &self.eth_cold_key.pk.raw {
                    common::PublicKey::Secp256k1(key) => key.clone(),
                    _ => unreachable!(),
                },
                protocol_key: self.protocol_key.pk.raw.clone(),
                commission_rate: self.commission_rate,
                max_commission_rate_change: self.max_commission_rate_change,
                email: self.metadata.email.clone(),
                description: self.metadata.description.clone(),
                website: self.metadata.website.clone(),
                discord_handle: self.metadata.discord_handle.clone(),
                avatar: self.metadata.avatar.clone(),
                name: self.metadata.name.clone(),
            },
        )
    }

    fn get_pks(
        &self,
        established_accounts: &[EstablishedAccountTx],
    ) -> (HashSet<PublicKey>, u8) {
        established_accounts
            .iter()
            .find_map(|account| {
                if account.derive_established_address() == self.address.raw {
                    Some((
                        account
                            .public_keys
                            .iter()
                            .map(|pk| pk.raw.clone())
                            .collect::<HashSet<_>>(),
                        account.threshold,
                    ))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                panic!(
                    "Cannot sign a pre-genesis tx because the established \
                     address {} could not be found",
                    self.address
                )
            })
    }

    fn get_owner(&self) -> GenesisAddress {
        GenesisAddress::EstablishedAddress(self.address.raw.clone())
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct EstablishedAccountTx {
    pub vp: String,
    #[serde(default = "default_threshold")]
    pub threshold: u8,
    /// PKs have to come last in TOML to avoid `ValueAfterTable` error
    pub public_keys: Vec<StringEncoded<common::PublicKey>>,
}

const fn default_threshold() -> u8 {
    1
}

impl DeriveEstablishedAddress for EstablishedAccountTx {
    const SALT: &'static str = "established-account-tx";
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct Signed<T> {
    #[serde(flatten)]
    pub data: T,
    pub signatures: BTreeMap<
        StringEncoded<common::PublicKey>,
        StringEncoded<common::Signature>,
    >,
}

impl<T> Signed<T> {
    /// Instantiate data to be signed.
    pub const fn new(data: T) -> Self {
        Self {
            data,
            signatures: BTreeMap::new(),
        }
    }

    /// Return the inner wrapped `T`.
    pub fn into_inner(self) -> T {
        let Signed { data, .. } = self;
        data
    }

    /// Sign the underlying data and add to the list of signatures.
    pub async fn sign(
        &mut self,
        established_accounts: &[EstablishedAccountTx],
        wallet_lock: &RwLock<Wallet<CliWalletUtils>>,
        use_device: bool,
        device_transport: DeviceTransport,
    ) where
        T: BorshSerialize + TxToSign,
    {
        let (pks, threshold) = self.data.get_pks(established_accounts);
        let owner = self.data.get_owner().address();
        let signing_data = SigningTxData {
            owner: Some(owner),
            account_public_keys_map: Some(pks.iter().cloned().collect()),
            public_keys: pks.clone(),
            threshold,
            fee_payer: Either::Left((genesis_fee_payer_pk(), false)),
            masp_sus_fee_payer: None,
            shielded_hash: None,
            signatures: vec![],
        };

        let mut tx = self.data.tx_to_sign();

        if use_device {
            let transport = WalletTransport::from_arg(device_transport);
            let app = NamadaApp::new(transport);
            sign_tx(
                wallet_lock,
                &get_tx_args(use_device),
                &mut tx,
                signing_data,
                utils::with_hardware_wallet,
                (wallet_lock, &app),
            )
            .await
            .expect("Failed to sign pre-genesis transaction.")
        } else {
            async fn software_wallet_sign(
                tx: Tx,
                pubkey: common::PublicKey,
                _parts: namada_sdk::signing::Signable,
                _user: (),
            ) -> Result<Tx, namada_sdk::error::Error> {
                if pubkey == genesis_fee_payer_pk() {
                    Ok(tx)
                } else {
                    Err(namada_sdk::error::Error::Other(format!(
                        "unable to sign transaction with {pubkey}",
                    )))
                }
            }

            sign_tx(
                wallet_lock,
                &get_tx_args(use_device),
                &mut tx,
                signing_data,
                software_wallet_sign,
                (),
            )
            .await
            .expect("Failed to sign pre-genesis transaction.");
        }

        let raw_header_hash = tx.raw_header_hash();
        let sigs = tx
            .sections
            .into_iter()
            .find_map(|sec| {
                if let Section::Authorization(signatures) = sec {
                    if [raw_header_hash] == signatures.targets.as_slice() {
                        Some(signatures)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                panic!(
                    "No signature could be produced for a transaction of type \
                     {}. The most likely cause is a missing secret key, \
                     public key hash or alias in your pre-genesis wallet.",
                    std::any::type_name::<T>()
                );
            });
        for (ix, sig) in sigs.signatures.into_iter() {
            self.signatures.insert(
                StringEncoded::new(pks[ix as usize].clone()),
                StringEncoded::new(sig),
            );
        }
    }

    /// Verify the signatures of the inner data.
    pub fn verify_sig(&self, threshold: u8) -> Result<(), String>
    where
        T: BorshSerialize + TxToSign,
    {
        let Self { data, signatures } = self;
        let (public_keys, signatures): (Vec<_>, Vec<_>) = signatures
            .iter()
            .map(|(pk, sig)| {
                (
                    pk.raw.clone(),
                    SignatureIndex {
                        index: None,
                        signature: sig.raw.clone(),
                        pubkey: pk.raw.clone(),
                    },
                )
            })
            .unzip();
        let signed_tx = {
            let mut tx = data.tx_to_sign();
            tx.add_signatures(signatures);
            tx
        };
        signed_tx
            .verify_signatures(
                &HashSet::from_iter([signed_tx.raw_header_hash()]),
                AccountPublicKeysMap::from_iter(public_keys.into_iter()),
                &None,
                threshold,
                || Ok(()),
            )
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct BondTx<T: TemplateValidation> {
    pub source: GenesisAddress,
    pub validator: Address,
    pub amount: T::Amount,
}

impl<T> TxToSign for BondTx<T>
where
    T: TemplateValidation + BorshSerialize,
{
    fn tx_to_sign(&self) -> Tx {
        get_tx_to_sign(
            TX_BOND_WASM,
            pos::Bond {
                validator: self.validator.clone(),
                amount: denominate_amount::<T>(self.amount.clone())
                    .unwrap()
                    .amount(),
                source: Some(self.source.address()),
            },
        )
    }

    fn get_pks(
        &self,
        established_accounts: &[EstablishedAccountTx],
    ) -> (HashSet<PublicKey>, u8) {
        match &self.source {
            GenesisAddress::PublicKey(pk) => ([pk.raw.clone()].into(), 1),
            GenesisAddress::EstablishedAddress(owner) => established_accounts
                .iter()
                .find_map(|account| {
                    if &account.derive_established_address() == owner {
                        Some((
                            account
                                .public_keys
                                .iter()
                                .map(|pk| pk.raw.clone())
                                .collect::<HashSet<_>>(),
                            account.threshold,
                        ))
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| {
                    panic!(
                        "Cannot sign a pre-genesis tx because the established \
                         address {} could not be found",
                        owner
                    )
                }),
        }
    }

    fn get_owner(&self) -> GenesisAddress {
        self.source.clone()
    }
}

impl BondTx<Unvalidated> {
    /// Add the correct denomination to the contained amount
    pub fn denominate(self) -> eyre::Result<BondTx<Validated>> {
        let amount = denominate_amount::<Unvalidated>(self.amount)?;
        Ok(BondTx {
            source: self.source,
            validator: self.validator,
            amount,
        })
    }
}

/// Return the correctly denominated amount of bonded tokens
fn denominate_amount<T>(
    amount: T::Amount,
) -> eyre::Result<token::DenominatedAmount>
where
    T: TemplateValidation,
{
    let amount = amount
        .into()
        .increase_precision(NATIVE_MAX_DECIMAL_PLACES.into())
        .map_err(|e| {
            eprintln!(
                "A bond amount in the transactions.toml file was incorrectly \
                 formatted:\n{}",
                e
            );
            e
        })?;
    Ok(amount)
}

impl<T: TemplateValidation> From<BondTx<T>> for SignedBondTx<T> {
    #[inline]
    fn from(bond: BondTx<T>) -> Self {
        Signed::new(bond)
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct SignedPk {
    pub pk: StringEncoded<common::PublicKey>,
    pub authorization: StringEncoded<common::Signature>,
}

pub fn validate(
    transactions: Transactions<Unvalidated>,
    vps: Option<&ValidityPredicates>,
    balances: Option<&DenominatedBalances>,
    parameters: Option<&Parameters<Validated>>,
) -> Option<Transactions<Validated>> {
    let mut is_valid = true;

    let mut all_used_addresses: BTreeSet<Address> = BTreeSet::default();
    let mut established_accounts: BTreeMap<
        Address,
        (Vec<common::PublicKey>, u8),
    > = BTreeMap::default();
    let mut validator_accounts = BTreeSet::new();

    let Transactions {
        ref established_account,
        ref validator_account,
        bond,
    } = transactions;

    if let Some(txs) = established_account {
        for tx in txs {
            if !validate_established_account(
                tx,
                vps,
                &mut all_used_addresses,
                &mut established_accounts,
            ) {
                is_valid = false;
            }
        }
    }

    if let Some(txs) = validator_account {
        for tx in txs {
            if !validate_validator_account(
                tx,
                vps,
                &all_used_addresses,
                &established_accounts,
                &mut validator_accounts,
            ) {
                is_valid = false;
            }
        }
    }

    // Make a mutable copy of the balances for tracking changes applied from txs
    let mut token_balances: BTreeMap<Alias, TokenBalancesForValidation> =
        balances
            .map(|balances| {
                balances
                    .token
                    .iter()
                    .map(|(token, token_balances)| {
                        (
                            token.clone(),
                            TokenBalancesForValidation {
                                amounts: token_balances.0.clone(),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

    let validated_bonds = if let Some(txs) = bond {
        if !txs.is_empty() {
            match parameters {
                Some(parameters) => {
                    let bond_number = txs.len();
                    let validated_bonds: Vec<_> = txs
                        .into_iter()
                        .filter_map(|tx| {
                            validate_bond(
                                tx,
                                &mut token_balances,
                                &established_accounts,
                                &validator_accounts,
                                parameters,
                            )
                        })
                        .collect();
                    if validated_bonds.len() != bond_number {
                        is_valid = false;
                        None
                    } else {
                        Some(validated_bonds)
                    }
                }
                None => {
                    eprintln!(
                        "Unable to validate bonds without a valid parameters \
                         file."
                    );
                    is_valid = false;
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    is_valid.then_some(Transactions {
        established_account: transactions.established_account,
        validator_account: transactions.validator_account.map(
            |validator_accounts| {
                validator_accounts
                    .into_iter()
                    .map(|acct| SignedValidatorAccountTx {
                        signatures: acct.signatures,
                        data: ValidatorAccountTx {
                            address: acct.data.address,
                            vp: acct.data.vp,
                            commission_rate: acct.data.commission_rate,
                            max_commission_rate_change: acct
                                .data
                                .max_commission_rate_change,
                            net_address: acct.data.net_address,
                            consensus_key: acct.data.consensus_key,
                            protocol_key: acct.data.protocol_key,
                            tendermint_node_key: acct.data.tendermint_node_key,
                            eth_hot_key: acct.data.eth_hot_key,
                            eth_cold_key: acct.data.eth_cold_key,
                            metadata: acct.data.metadata,
                        },
                    })
                    .collect()
            },
        ),
        bond: validated_bonds,
    })
}

fn validate_bond(
    tx: SignedBondTx<Unvalidated>,
    balances: &mut BTreeMap<Alias, TokenBalancesForValidation>,
    established_accounts: &BTreeMap<Address, (Vec<common::PublicKey>, u8)>,
    validator_accounts: &BTreeSet<Address>,
    parameters: &Parameters<Validated>,
) -> Option<BondTx<Validated>> {
    // Check signature
    let mut is_valid = {
        let source = &tx.data.source;
        let maybe_threshold = match source {
            GenesisAddress::EstablishedAddress(address) => {
                // Try to find the source's PK in either established_accounts or
                // validator_accounts
                let established_addr = Address::Established(address.clone());
                established_accounts.get(&established_addr).map(|(_, t)| *t)
            }
            GenesisAddress::PublicKey(_) => Some(1),
        };
        if let Some(threshold) = maybe_threshold {
            if let Err(err) = tx.verify_sig(threshold) {
                eprintln!("Invalid bond tx signature: {err}");
                false
            } else {
                true
            }
        } else {
            eprintln!(
                "Invalid bond tx. Couldn't verify bond's signature, because \
                 the source accounts \"{source}\" public key cannot be found."
            );
            false
        }
    };

    // Make sure the native token amount is denominated correctly
    let validated_bond = tx.data.denominate().ok()?;
    let BondTx {
        source,
        validator,
        amount,
        ..
    } = &validated_bond;

    // Check that the validator exists
    if !validator_accounts.contains(validator) {
        eprintln!(
            "Invalid bond tx. The target validator \"{validator}\" account \
             not found."
        );
        is_valid = false;
    }

    // Check and update token balance of the source
    let native_token = &parameters.parameters.native_token;
    let source = source.address();
    match balances.get_mut(native_token) {
        Some(balances) => {
            let balance = balances.amounts.get_mut(&source);
            match balance {
                Some(balance) => {
                    if *balance < *amount {
                        eprintln!(
                            "Invalid bond tx. Source {source} doesn't have \
                             enough balance of token \"{native_token}\" to \
                             transfer {}. Got {}.",
                            amount, balance,
                        );
                        is_valid = false;
                    } else {
                        // Deduct the amount from source
                        if amount == balance {
                            balances.amounts.remove(&source);
                        } else if let Some(new_balance) =
                            balance.checked_sub(*amount)
                        {
                            *balance = new_balance;
                        } else {
                            eprintln!(
                                "Invalid bond tx. Amount {} should have the \
                                 denomination {:?}. Got {:?}.",
                                amount,
                                balance.denom(),
                                amount.denom(),
                            );
                            is_valid = false;
                        }
                    }
                }
                None => {
                    eprintln!(
                        "Invalid transfer tx. Source {source} has no balance \
                         of token \"{native_token}\"."
                    );
                    is_valid = false;
                }
            }
        }
        None => {
            eprintln!(
                "Invalid bond tx. Token \"{native_token}\" not found in \
                 balances."
            );
            is_valid = false;
        }
    }

    is_valid.then_some(validated_bond)
}

#[derive(Clone, Debug)]
pub struct TokenBalancesForValidation {
    /// Accumulator for tokens transferred to accounts
    pub amounts: BTreeMap<Address, DenominatedAmount>,
}

pub fn validate_established_account(
    tx: &EstablishedAccountTx,
    vps: Option<&ValidityPredicates>,
    all_used_addresses: &mut BTreeSet<Address>,
    established_accounts: &mut BTreeMap<Address, (Vec<common::PublicKey>, u8)>,
) -> bool {
    let mut is_valid = true;

    let established_address = tx.derive_address();
    if tx.threshold == 0 {
        eprintln!("An established account may not have zero threshold");
        is_valid = false;
    }
    if tx.threshold as usize > tx.public_keys.len() {
        eprintln!(
            "An established account may not have a threshold ({}) greater \
             than the number of public keys associated with it ({})",
            tx.threshold,
            tx.public_keys.len()
        );
        is_valid = false;
    }
    if tx.public_keys.len() > u8::MAX as usize {
        eprintln!(
            "The number of configured public keys is way too fucking big"
        );
        is_valid = false;
    }
    {
        // check for duped pubkeys
        let mut used_keys = HashSet::new();
        for key in tx.public_keys.iter() {
            if !used_keys.insert(key) {
                eprintln!(
                    "The same public key has been used twice in an \
                     established account tx: {key}"
                );
                is_valid = false;
            }
        }
    }
    established_accounts.insert(
        established_address.clone(),
        (
            tx.public_keys.iter().map(|k| k.raw.clone()).collect(),
            tx.threshold,
        ),
    );

    // Check that the established address is unique
    if all_used_addresses.contains(&established_address) {
        eprintln!(
            "A duplicate address \"{}\" found in a `established_account` tx.",
            established_address
        );
        is_valid = false;
    } else {
        all_used_addresses.insert(established_address);
    }

    // Check the VP exists
    if !vps
        .map(|vps| vps.wasm.contains_key(&tx.vp))
        .unwrap_or_default()
    {
        eprintln!(
            "An `established_account` tx `vp` \"{}\" not found in Validity \
             predicates file.",
            tx.vp
        );
        is_valid = false;
    }

    // If PK is used, check the authorization
    if tx.public_keys.is_empty() {
        eprintln!("An `established_account` tx was found with no public keys.");
        is_valid = false;
    }
    is_valid
}

pub fn validate_validator_account(
    signed_tx: &SignedValidatorAccountTx,
    vps: Option<&ValidityPredicates>,
    all_used_addresses: &BTreeSet<Address>,
    established_accounts: &BTreeMap<Address, (Vec<common::PublicKey>, u8)>,
    validator_accounts: &mut BTreeSet<Address>,
) -> bool {
    let tx = &signed_tx.data;

    // Check eth keys are secp256k1 keys
    if !matches!(
        &signed_tx.data.eth_cold_key.pk.raw,
        common::PublicKey::Secp256k1(_)
    ) {
        panic!(
            "The validator with address {} has a non Secp256k1 Ethereum cold \
             key",
            signed_tx.data.address
        );
    }
    if !matches!(
        &signed_tx.data.eth_hot_key.pk.raw,
        common::PublicKey::Secp256k1(_)
    ) {
        panic!(
            "The validator with address {} has a non Secp256k1 Ethereum hot \
             key",
            signed_tx.data.address
        );
    }

    // Check that the validator metadata is not too large
    let metadata = &signed_tx.data.metadata;
    let errors = metadata.validate();
    if !errors.is_empty() {
        panic!(
            "Metadata of the validator with address {} are invalid: \
             {errors:#?}",
            signed_tx.data.address
        );
    }

    // Check signature
    let mut is_valid = {
        let maybe_threshold = {
            let established_addr = Address::Established(tx.address.raw.clone());
            established_accounts.get(&established_addr).map(|(pks, t)| {
                let all_ed25519_keys = pks
                    .iter()
                    .all(|key| matches!(key, common::PublicKey::Ed25519(_)));
                if !all_ed25519_keys {
                    panic!(
                        "Not all account keys of the validator with address \
                         {established_addr} are Ed25519 keys"
                    );
                }
                *t
            })
        };
        if let Some(threshold) = maybe_threshold {
            if let Err(err) = signed_tx.verify_sig(threshold) {
                eprintln!("Invalid validator account signature: {err}");
                false
            } else {
                true
            }
        } else {
            let source = &tx.address.raw;
            eprintln!(
                "Invalid validator account tx. Couldn't verify the underlying \
                 established account signatures, because the source account's \
                 \"{source}\" public keys cannot be found."
            );
            false
        }
    };

    let established_address = {
        let established_address = Address::Established(tx.address.raw.clone());
        if !all_used_addresses.contains(&established_address) {
            eprintln!(
                "Unable to find established account with address \"{}\" in a \
                 `validator_account` tx, to initialize a new validator with.",
                established_address
            );
            is_valid = false;
        }
        if validator_accounts.contains(&established_address) {
            eprintln!(
                "A duplicate validator \"{}\" found in a `validator_account` \
                 tx.",
                established_address
            );
            is_valid = false;
        } else {
            validator_accounts.insert(established_address.clone());
        }
        established_address
    };

    // Check the VP exists
    if !vps
        .map(|vps| vps.wasm.contains_key(&tx.vp))
        .unwrap_or_default()
    {
        eprintln!(
            "A `validator_account` tx `vp` \"{}\" not found in Validity \
             predicates file.",
            tx.vp
        );
        is_valid = false;
    }

    // Check keys authorizations
    let unsigned = UnsignedValidatorAccountTx::from(tx);
    if !validate_signature(
        &unsigned,
        &tx.consensus_key.pk.raw,
        &tx.consensus_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `consensus_key` authorization for `validator_account` tx \
             with address \"{}\".",
            established_address
        );
        is_valid = false;
    }
    if !validate_signature(
        &unsigned,
        &tx.protocol_key.pk.raw,
        &tx.protocol_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `protocol_key` authorization for `validator_account` tx \
             with address \"{}\".",
            established_address
        );
        is_valid = false;
    }
    if !validate_signature(
        &unsigned,
        &tx.tendermint_node_key.pk.raw,
        &tx.tendermint_node_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `tendermint_node_key` authorization for \
             `validator_account` tx with address \"{}\".",
            established_address
        );
        is_valid = false;
    }

    if !validate_signature(
        &unsigned,
        &tx.eth_hot_key.pk.raw,
        &tx.eth_hot_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `eth_hot_key` authorization for `validator_account` tx \
             with address \"{}\".",
            established_address
        );
        is_valid = false;
    }

    if !validate_signature(
        &unsigned,
        &tx.eth_cold_key.pk.raw,
        &tx.eth_cold_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `eth_cold_key` authorization for `validator_account` tx \
             with address \"{}\".",
            established_address
        );
        is_valid = false;
    }

    is_valid
}

fn validate_signature<T: BorshSerialize + Debug>(
    tx_data: &T,
    pk: &common::PublicKey,
    sig: &common::Signature,
) -> bool {
    match verify_standalone_sig::<T, SerializeWithBorsh>(tx_data, pk, sig) {
        Ok(()) => true,
        Err(err) => {
            eprintln!(
                "Invalid tx signature in tx {tx_data:?}, failed with: {err}."
            );
            false
        }
    }
}

impl From<&ValidatorAccountTx<SignedPk>> for UnsignedValidatorAccountTx {
    fn from(tx: &ValidatorAccountTx<SignedPk>) -> Self {
        let ValidatorAccountTx {
            address,
            vp,
            commission_rate,
            max_commission_rate_change,
            metadata,
            net_address,
            consensus_key,
            protocol_key,
            tendermint_node_key,
            eth_hot_key,
            eth_cold_key,
            ..
        } = tx;

        Self {
            address: address.clone(),
            vp: vp.clone(),
            commission_rate: *commission_rate,
            max_commission_rate_change: *max_commission_rate_change,
            metadata: metadata.clone(),
            net_address: *net_address,
            consensus_key: consensus_key.pk.clone(),
            protocol_key: protocol_key.pk.clone(),
            tendermint_node_key: tendermint_node_key.pk.clone(),
            eth_hot_key: eth_hot_key.pk.clone(),
            eth_cold_key: eth_cold_key.pk.clone(),
        }
    }
}
