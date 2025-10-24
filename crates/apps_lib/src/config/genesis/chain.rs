use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use eyre::eyre;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_sdk::address::{
    Address, EstablishedAddress, EstablishedAddressGen, InternalAddress,
};
use namada_sdk::borsh::{BorshDeserialize, BorshSerialize, BorshSerializeExt};
use namada_sdk::chain::{ChainId, ChainIdPrefix};
use namada_sdk::governance::pgf::parameters::PgfParameters;
use namada_sdk::hash::Hash;
use namada_sdk::ibc::parameters::{IbcParameters, IbcTokenRateLimits};
use namada_sdk::key::{RefTo, common};
use namada_sdk::parameters::EpochDuration;
use namada_sdk::time::{DateTimeUtc, DurationNanos, Rfc3339String};
use namada_sdk::token::Amount;
use namada_sdk::wallet::store::AddressVpType;
use namada_sdk::wallet::{Wallet, pre_genesis};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::utils::{read_toml, write_toml};
use super::{templates, transactions};
use crate::config::genesis::templates::Validated;
use crate::config::utils::{set_ip, set_port};
use crate::config::{Config, TendermintMode};
use crate::tendermint::node::Id as TendermintNodeId;
use crate::tendermint_config::net::Address as TendermintAddress;
use crate::tendermint_node::id_from_pk;
use crate::wallet::{Alias, CliWalletUtils};
use crate::wasm_loader;

pub const METADATA_FILE_NAME: &str = "chain.toml";

/// Derive established addresses from seed data.
pub trait DeriveEstablishedAddress {
    /// Arbitrary data to hash the seed data with.
    const SALT: &'static str;

    /// Derive an established address.
    fn derive_established_address(&self) -> EstablishedAddress
    where
        Self: BorshSerialize,
    {
        let mut hasher = Sha256::new();
        hasher.update(Self::SALT.as_bytes());
        hasher.update(self.serialize_to_vec());
        let digest = hasher.finalize();
        let digest_ref: &[u8; 32] = digest.as_ref();
        EstablishedAddress::from(*digest_ref)
    }

    /// Derive an address.
    #[inline]
    fn derive_address(&self) -> Address
    where
        Self: BorshSerialize,
    {
        Address::Established(self.derive_established_address())
    }
}

impl Finalized {
    /// Write all genesis and the chain metadata TOML files to the given
    /// directory.
    pub fn write_toml_files(&self, output_dir: &Path) -> eyre::Result<()> {
        let vps_file = output_dir.join(templates::VPS_FILE_NAME);
        let tokens_file = output_dir.join(templates::TOKENS_FILE_NAME);
        let balances_file = output_dir.join(templates::BALANCES_FILE_NAME);
        let parameters_file = output_dir.join(templates::PARAMETERS_FILE_NAME);
        let transactions_file =
            output_dir.join(templates::TRANSACTIONS_FILE_NAME);
        let metadata_file = output_dir.join(METADATA_FILE_NAME);

        write_toml(&self.vps, &vps_file, "Validity predicates")?;
        write_toml(&self.tokens, &tokens_file, "Tokens")?;
        write_toml(&self.balances, &balances_file, "Balances")?;
        write_toml(&self.parameters, &parameters_file, "Parameters")?;
        write_toml(&self.transactions, &transactions_file, "Transactions")?;
        write_toml(&self.metadata, &metadata_file, "Chain metadata")?;
        Ok(())
    }

    /// Attempt to read the address of the native token.
    pub fn read_native_token(input_dir: &Path) -> eyre::Result<Address> {
        let tokens_file = input_dir.join(templates::TOKENS_FILE_NAME);
        let parameters_file = input_dir.join(templates::PARAMETERS_FILE_NAME);

        let mut tokens: FinalizedTokens = read_toml(&tokens_file, "Tokens")?;
        let parameters: FinalizedParameters =
            read_toml(&parameters_file, "Parameters")?;

        let alias = &parameters.parameters.native_token;

        Ok(tokens
            .token
            .remove(alias)
            .expect("The native token must exist")
            .address)
    }

    /// Try to read all genesis and the chain metadata TOML files from the given
    /// directory.
    ///
    /// The consistency of the files is checked with [`Finalized::is_valid`].
    pub fn read_toml_files(input_dir: &Path) -> eyre::Result<Self> {
        let vps_file = input_dir.join(templates::VPS_FILE_NAME);
        let tokens_file = input_dir.join(templates::TOKENS_FILE_NAME);
        let balances_file = input_dir.join(templates::BALANCES_FILE_NAME);
        let parameters_file = input_dir.join(templates::PARAMETERS_FILE_NAME);
        let transactions_file =
            input_dir.join(templates::TRANSACTIONS_FILE_NAME);
        let metadata_file = input_dir.join(METADATA_FILE_NAME);

        let vps = read_toml(&vps_file, "Validity predicates")?;
        let tokens = read_toml(&tokens_file, "Tokens")?;
        let balances = read_toml(&balances_file, "Balances")?;
        let parameters = read_toml(&parameters_file, "Parameters")?;
        let transactions = read_toml(&transactions_file, "Transactions")?;
        let metadata = read_toml(&metadata_file, "Chain metadata")?;
        let genesis = Self {
            vps,
            tokens,
            balances,
            parameters,
            transactions,
            metadata,
        };

        if !genesis.is_valid() {
            return Err(eyre!("Invalid genesis files"));
        }

        Ok(genesis)
    }

    /// Find the address of the configured native token
    pub fn get_native_token(&self) -> &Address {
        let alias = &self.parameters.parameters.native_token;
        &self
            .tokens
            .token
            .get(alias)
            .expect("The native token must exist")
            .address
    }

    /// Derive Namada wallet from genesis
    pub fn derive_wallet(
        &self,
        base_dir: &Path,
        pre_genesis_wallet: Option<Wallet<CliWalletUtils>>,
        validator: Option<(Alias, pre_genesis::ValidatorWallet)>,
    ) -> Wallet<CliWalletUtils> {
        let mut wallet = crate::wallet::load_or_new(base_dir);
        for (alias, config) in &self.tokens.token {
            wallet.insert_address(
                alias.normalize(),
                config.address.clone(),
                false,
            );
            wallet.add_vp_type_to_address(
                AddressVpType::Token,
                config.address.clone(),
            );
        }
        if let Some(pre_genesis_wallet) = pre_genesis_wallet {
            wallet.extend(pre_genesis_wallet);
        }
        if let Some((alias, validator_wallet)) = validator {
            let tendermint_pk = validator_wallet.tendermint_node_key.ref_to();
            let address = self
                .transactions
                .find_validator(&tendermint_pk)
                .map(|tx| Address::Established(tx.tx.data.address.raw.clone()))
                .expect("Validator alias not found in genesis transactions.");
            wallet.extend_from_pre_genesis_validator(
                address.clone(),
                alias.clone(),
                validator_wallet,
            );
        }

        // Add some internal addresses to the wallet
        for int_add in &[
            InternalAddress::PoS,
            InternalAddress::Masp,
            InternalAddress::Ibc,
            InternalAddress::Governance,
            InternalAddress::Pgf,
        ] {
            wallet.insert_address(
                int_add.to_string().to_lowercase(),
                Address::Internal(int_add.clone()),
                false,
            );
        }

        wallet
    }

    /// Derive Namada configuration from genesis
    pub fn derive_config(
        &self,
        base_dir: &Path,
        node_mode: TendermintMode,
        tendermint_pk: Option<&common::PublicKey>,
        allow_duplicate_ip: bool,
        add_persistent_peers: bool,
    ) -> Config {
        if node_mode != TendermintMode::Validator && tendermint_pk.is_some() {
            println!(
                "Warning: Validator alias used to derive config, but node \
                 mode is not validator, it is {node_mode:?}!"
            );
        }
        let mut config =
            Config::new(base_dir, self.metadata.chain_id.clone(), node_mode);

        // Derive persistent peers from genesis
        let persistent_peers =
            self.derive_persistent_peers(add_persistent_peers);
        // If `tendermint_pk` is given, find its net_address
        let validator_net_and_tm_address =
            if let Some(tendermint_pk) = tendermint_pk {
                self.transactions.find_validator(tendermint_pk).map(
                    |validator_tx| {
                        (
                            validator_tx.tx.data.net_address,
                            validator_tx.derive_tendermint_address(),
                        )
                    },
                )
            } else {
                None
            };
        // Check if the validators are localhost to automatically turn off
        // Tendermint P2P address book strict mode to allow it
        let is_localhost = persistent_peers.iter().all(|peer| match peer {
            TendermintAddress::Tcp {
                peer_id: _,
                host,
                port: _,
            } => matches!(host.as_str(), "127.0.0.1" | "localhost"),
            TendermintAddress::Unix { path: _ } => false,
        });

        // Configure the ledger
        config.ledger.genesis_time = self.metadata.genesis_time.clone();

        // Add a ledger P2P persistent peers
        config.ledger.cometbft.p2p.persistent_peers = persistent_peers;
        config.ledger.cometbft.consensus.timeout_commit =
            self.metadata.consensus_timeout_commit.into();
        config.ledger.cometbft.p2p.allow_duplicate_ip = allow_duplicate_ip;
        config.ledger.cometbft.p2p.addr_book_strict = !is_localhost;

        if let Some((net_address, tm_address)) = validator_net_and_tm_address {
            // Take out address of self from the P2P persistent peers
            config.ledger.cometbft.p2p.persistent_peers = config.ledger.cometbft.p2p.persistent_peers.iter()
                        .filter_map(|peer|
                            // we do not add the validator in its own persistent peer list
                            if peer != &tm_address  {
                                Some(peer.to_owned())
                            } else {
                                None
                            })
                        .collect();

            let first_port = net_address.port();
            if !is_localhost {
                set_ip(&mut config.ledger.cometbft.p2p.laddr, "0.0.0.0");
            }
            set_port(&mut config.ledger.cometbft.p2p.laddr, first_port);
            if !is_localhost {
                set_ip(&mut config.ledger.cometbft.rpc.laddr, "0.0.0.0");
            }
            set_port(
                &mut config.ledger.cometbft.rpc.laddr,
                first_port.checked_add(1).expect("Port must not overflow"),
            );
            set_port(
                &mut config.ledger.cometbft.proxy_app,
                first_port.checked_add(2).expect("Port must not overflow"),
            );

            // Validator node should turned off peer exchange reactor
            config.ledger.cometbft.p2p.pex = false;
        }

        config
    }

    /// Derive persistent peers from genesis validators
    fn derive_persistent_peers(
        &self,
        add_persistent_peers: bool,
    ) -> Vec<TendermintAddress> {
        add_persistent_peers.then(|| {
            self.transactions
                .validator_account
                .as_ref()
                .map(|txs| {
                    txs.iter()
                        .map(FinalizedValidatorAccountTx::derive_tendermint_address)
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default()
    }

    /// Get the chain parameters set in genesis
    pub fn get_chain_parameters(
        &self,
        wasm_dir: impl AsRef<Path>,
    ) -> namada_sdk::parameters::Parameters {
        let templates::ChainParams {
            min_num_of_blocks,
            max_proposal_bytes,
            vp_allowlist,
            tx_allowlist,
            implicit_vp,
            epochs_per_year,
            masp_epoch_multiplier,
            masp_fee_payment_gas_limit,
            gas_scale,
            max_block_gas,
            minimum_gas_price,
            max_tx_bytes,
            is_native_token_transferable,
            ..
        } = self.parameters.parameters.clone();

        let implicit_vp_filename = &self
            .vps
            .wasm
            .get(&implicit_vp)
            .expect("Implicit VP must be present")
            .filename;

        let implicit_vp_code_hash =
            wasm_loader::read_wasm(&wasm_dir, implicit_vp_filename)
                .ok()
                .map(Hash::sha256);

        let epy_i64 = i64::try_from(epochs_per_year)
            .expect("`epochs_per_year` must not exceed `i64::MAX`");
        #[allow(clippy::arithmetic_side_effects)]
        let min_duration: i64 = 60 * 60 * 24 * 365 / epy_i64;
        let epoch_duration = EpochDuration {
            min_num_of_blocks,
            min_duration: namada_sdk::time::Duration::seconds(min_duration)
                .into(),
        };
        let vp_allowlist = vp_allowlist.unwrap_or_default();
        let tx_allowlist = tx_allowlist.unwrap_or_default();

        namada_sdk::parameters::Parameters {
            max_tx_bytes,
            epoch_duration,
            vp_allowlist,
            tx_allowlist,
            implicit_vp_code_hash,
            epochs_per_year,
            masp_epoch_multiplier,
            max_proposal_bytes,
            masp_fee_payment_gas_limit,
            gas_scale,
            max_block_gas,
            minimum_gas_price: minimum_gas_price
                .iter()
                .map(|(token, amt)| {
                    (
                        self.tokens.token.get(token).cloned().unwrap().address,
                        amt.amount(),
                    )
                })
                .collect(),
            is_native_token_transferable,
        }
    }

    pub fn get_pos_params(
        &self,
    ) -> namada_sdk::proof_of_stake::parameters::PosParams {
        let templates::PosParams {
            max_validator_slots,
            pipeline_len,
            unbonding_len,
            tm_votes_per_token,
            block_proposer_reward,
            block_vote_reward,
            max_inflation_rate,
            target_staked_ratio,
            duplicate_vote_min_slash_rate,
            light_client_attack_min_slash_rate,
            cubic_slashing_window_length,
            validator_stake_threshold,
            liveness_window_check,
            liveness_threshold,
            rewards_gain_p,
            rewards_gain_d,
        } = self.parameters.pos_params.clone();

        namada_sdk::proof_of_stake::parameters::PosParams {
            owned: namada_sdk::proof_of_stake::parameters::OwnedPosParams {
                max_validator_slots,
                pipeline_len,
                unbonding_len,
                tm_votes_per_token,
                block_proposer_reward,
                block_vote_reward,
                max_inflation_rate,
                target_staked_ratio,
                duplicate_vote_min_slash_rate,
                light_client_attack_min_slash_rate,
                cubic_slashing_window_length,
                validator_stake_threshold,
                liveness_window_check,
                liveness_threshold,
                rewards_gain_p,
                rewards_gain_d,
            },
            max_proposal_period: self.parameters.gov_params.max_proposal_period,
        }
    }

    pub fn get_gov_params(
        &self,
    ) -> namada_sdk::governance::parameters::GovernanceParameters {
        let templates::GovernanceParams {
            min_proposal_fund,
            max_proposal_code_size,
            min_proposal_voting_period,
            max_proposal_period,
            max_proposal_content_size,
            min_proposal_grace_epochs,
            max_proposal_latency,
        } = self.parameters.gov_params.clone();
        namada_sdk::governance::parameters::GovernanceParameters {
            min_proposal_fund: Amount::native_whole(min_proposal_fund),
            max_proposal_code_size,
            max_proposal_period,
            max_proposal_content_size,
            min_proposal_grace_epochs,
            min_proposal_voting_period,
            max_proposal_latency,
        }
    }

    pub fn get_pgf_params(&self) -> PgfParameters {
        self.parameters.pgf_params.clone()
    }

    pub fn get_ibc_params(&self) -> IbcParameters {
        let templates::IbcParams {
            default_mint_limit,
            default_per_epoch_throughput_limit,
        } = self.parameters.ibc_params.clone();
        IbcParameters {
            default_rate_limits: IbcTokenRateLimits {
                mint_limit: default_mint_limit,
                throughput_per_epoch_limit: default_per_epoch_throughput_limit,
            },
        }
    }

    pub fn get_token_address(&self, alias: &Alias) -> Option<&Address> {
        self.tokens.token.get(alias).map(|token| &token.address)
    }

    // Validate the chain ID against the genesis contents
    pub fn is_valid(&self) -> bool {
        let Self {
            vps,
            tokens,
            balances,
            parameters,
            transactions,
            metadata,
        } = self.clone();
        let Metadata {
            chain_id,
            genesis_time,
            consensus_timeout_commit,
            address_gen,
        } = metadata.clone();

        let Some(chain_id_prefix) = chain_id.prefix() else {
            tracing::warn!(
                "Invalid Chain ID \"{chain_id}\" - unable to find a prefix"
            );
            return false;
        };
        let metadata = Metadata {
            chain_id: chain_id_prefix.clone(),
            genesis_time,
            consensus_timeout_commit,
            address_gen,
        };
        let to_finalize = ToFinalize {
            vps,
            tokens,
            balances,
            parameters,
            transactions,
            metadata,
        };
        let derived_chain_id = derive_chain_id(chain_id_prefix, &to_finalize);
        let is_valid = derived_chain_id == chain_id;
        if !is_valid {
            tracing::warn!(
                "Invalid chain ID. This indicates that something in the \
                 genesis files might have been modified."
            );
        }
        is_valid
    }
}

/// Create the [`Finalized`] chain configuration. Derives the chain ID from the
/// genesis bytes and assigns addresses to tokens and transactions that
/// initialize established accounts.
///
/// Invariant: The output must deterministic. For the same input this function
/// must return the same output.
pub fn finalize(
    templates: templates::All<Validated>,
    chain_id_prefix: ChainIdPrefix,
    genesis_time: DateTimeUtc,
    consensus_timeout_commit: crate::tendermint::Timeout,
) -> Finalized {
    let genesis_time: Rfc3339String = genesis_time.into();
    let consensus_timeout_commit: DurationNanos =
        consensus_timeout_commit.into();

    // Derive seed for address generator
    let genesis_to_gen_address = GenesisToGenAddresses {
        templates,
        metadata: Metadata {
            chain_id: chain_id_prefix.clone(),
            genesis_time,
            consensus_timeout_commit,
            address_gen: None,
        },
    };
    let genesis_bytes = genesis_to_gen_address.serialize_to_vec();
    let addr_gen = established_address_gen(&genesis_bytes);

    // Generate addresses
    let templates::All {
        vps,
        tokens,
        balances,
        parameters,
        transactions,
    } = genesis_to_gen_address.templates;
    let tokens = FinalizedTokens::finalize_from(tokens);
    let transactions = FinalizedTransactions::finalize_from(transactions);
    let parameters = FinalizedParameters::finalize_from(parameters);

    // Store the last state of the address generator in the metadata
    let mut metadata = genesis_to_gen_address.metadata;
    metadata.address_gen = Some(addr_gen);

    // Derive chain ID
    let to_finalize = ToFinalize {
        metadata,
        vps,
        tokens,
        balances,
        parameters,
        transactions,
    };
    let chain_id = derive_chain_id(chain_id_prefix, &to_finalize);

    // Construct the `Finalized` chain
    let ToFinalize {
        vps,
        tokens,
        balances,
        parameters,
        transactions,
        metadata,
    } = to_finalize;
    let Metadata {
        chain_id: _,
        genesis_time,
        consensus_timeout_commit,
        address_gen,
    } = metadata;
    let metadata = Metadata {
        chain_id,
        genesis_time,
        consensus_timeout_commit,
        address_gen,
    };
    Finalized {
        metadata,
        vps,
        tokens,
        balances,
        parameters,
        transactions,
    }
}

/// Derive a chain ID from genesis contents
pub fn derive_chain_id(
    chain_id_prefix: ChainIdPrefix,
    to_finalize: &ToFinalize,
) -> ChainId {
    let to_finalize_bytes = to_finalize.serialize_to_vec();
    ChainId::from_genesis(chain_id_prefix, to_finalize_bytes)
}

/// Chain genesis config to be finalized. This struct is used to derive the
/// chain ID to construct a [`Finalized`] chain genesis config.
#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct GenesisToGenAddresses {
    /// Filled-in templates
    pub templates: templates::All<Validated>,
    /// Chain metadata
    pub metadata: Metadata<ChainIdPrefix>,
}

/// Chain genesis config to be finalized. This struct is used to derive the
/// chain ID to construct a [`Finalized`] chain genesis config.
pub type ToFinalize = Chain<ChainIdPrefix>;

/// Chain genesis config.
pub type Finalized = Chain<ChainId>;

/// Use bytes as a deterministic seed for address generator.
fn established_address_gen(bytes: &[u8]) -> EstablishedAddressGen {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    // hex of the first 40 chars of the hash
    let hash = format!("{:.width$X}", hasher.finalize(), width = 40);
    EstablishedAddressGen::new(hash)
}

/// Chain genesis config with generic chain ID.
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
pub struct Chain<ID> {
    pub vps: templates::ValidityPredicates,
    pub tokens: FinalizedTokens,
    pub balances: templates::DenominatedBalances,
    pub parameters: FinalizedParameters,
    pub transactions: FinalizedTransactions,
    /// Chain metadata
    pub metadata: Metadata<ID>,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedTokens {
    pub token: BTreeMap<Alias, FinalizedTokenConfig>,
}

impl FinalizedTokens {
    fn finalize_from(tokens: templates::Tokens) -> FinalizedTokens {
        let templates::Tokens { token } = tokens;
        let token = token
            .into_iter()
            .map(|(key, config)| {
                let address = Address::Established(
                    (&key, &config).derive_established_address(),
                );
                (key, FinalizedTokenConfig { address, config })
            })
            .collect();
        FinalizedTokens { token }
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedTokenConfig {
    pub address: Address,
    #[serde(flatten)]
    pub config: templates::TokenConfig,
}

impl DeriveEstablishedAddress for (&Alias, &templates::TokenConfig) {
    const SALT: &'static str = "token-config";
}

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedTransactions {
    pub established_account: Option<Vec<FinalizedEstablishedAccountTx>>,
    pub validator_account: Option<Vec<FinalizedValidatorAccountTx>>,
    pub bond: Option<Vec<transactions::BondTx<Validated>>>,
}

impl FinalizedTransactions {
    fn finalize_from(
        transactions: transactions::Transactions<Validated>,
    ) -> FinalizedTransactions {
        let transactions::Transactions {
            established_account,
            validator_account,
            bond,
        } = transactions;
        let established_account = established_account.map(|txs| {
            txs.into_iter()
                .map(|tx| FinalizedEstablishedAccountTx {
                    address: tx.derive_address(),
                    tx,
                })
                .collect()
        });
        let validator_account = validator_account.map(|txs| {
            txs.into_iter()
                .map(|tx| FinalizedValidatorAccountTx { tx })
                .collect()
        });
        FinalizedTransactions {
            established_account,
            validator_account,
            bond,
        }
    }

    fn find_validator(
        &self,
        tendermint_pk: &common::PublicKey,
    ) -> Option<&FinalizedValidatorAccountTx> {
        let validator_accounts = self.validator_account.as_ref()?;
        validator_accounts
            .iter()
            .find(|tx| &tx.tx.data.tendermint_node_key.pk.raw == tendermint_pk)
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedParameters {
    pub parameters: templates::ChainParams<Validated>,
    pub pos_params: templates::PosParams,
    pub gov_params: templates::GovernanceParams,
    pub pgf_params: PgfParameters,
    pub ibc_params: templates::IbcParams,
}

impl FinalizedParameters {
    fn finalize_from(
        templates::Parameters {
            parameters,
            pos_params,
            gov_params,
            pgf_params,
            ibc_params,
        }: templates::Parameters<Validated>,
    ) -> Self {
        let finalized_pgf_params = PgfParameters {
            stewards: pgf_params.stewards,
            pgf_inflation_rate: pgf_params.pgf_inflation_rate,
            stewards_inflation_rate: pgf_params.stewards_inflation_rate,
            maximum_number_of_stewards: pgf_params.maximum_number_of_stewards,
        };
        Self {
            parameters,
            pos_params,
            gov_params,
            pgf_params: finalized_pgf_params,
            ibc_params,
        }
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
)]
pub struct FinalizedEstablishedAccountTx {
    pub address: Address,
    #[serde(flatten)]
    pub tx: transactions::EstablishedAccountTx,
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
)]
pub struct FinalizedValidatorAccountTx {
    #[serde(flatten)]
    pub tx: transactions::SignedValidatorAccountTx,
}

impl FinalizedValidatorAccountTx {
    pub fn derive_tendermint_address(&self) -> TendermintAddress {
        // Derive the node ID from the node key
        let node_id: TendermintNodeId =
            id_from_pk(&self.tx.data.tendermint_node_key.pk.raw);

        // Build the list of persistent peers from the validators' node IDs
        TendermintAddress::from_str(&format!(
            "{}@{}",
            node_id, self.tx.data.net_address,
        ))
        .expect("Validator address must be valid")
    }
}

/// Chain metadata
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
pub struct Metadata<ID> {
    /// Chain ID in [`Finalized`] or chain ID prefix in
    /// [`GenesisToGenAddresses`] and [`ToFinalize`].
    pub chain_id: ID,
    // Genesis timestamp
    pub genesis_time: Rfc3339String,
    /// The Tendermint consensus timeout_commit configuration
    pub consensus_timeout_commit: DurationNanos,
    /// This generator should be used to initialize the ledger for the
    /// next address that will be generated on chain.
    ///
    /// The value is expected to always be `None` in [`GenesisToGenAddresses`]
    /// and `Some` in [`ToFinalize`] and [`Finalized`].
    pub address_gen: Option<EstablishedAddressGen>,
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use super::*;
    use crate::time::test_utils::GENESIS_TIME;

    /// Test that the [`finalize`] returns deterministic output with the same
    /// chain ID for the same input.
    #[test]
    fn test_finalize_is_deterministic() {
        // Load the localnet templates
        let templates_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("genesis/localnet");
        let templates = templates::load_and_validate(&templates_dir).unwrap();

        let chain_id_prefix: ChainIdPrefix =
            FromStr::from_str("test-prefix").unwrap();

        let genesis_time = DateTimeUtc::from_str(GENESIS_TIME).unwrap();

        let consensus_timeout_commit =
            crate::tendermint::Timeout::from_str("1s").unwrap();

        let finalized_0 = finalize(
            templates.clone(),
            chain_id_prefix.clone(),
            genesis_time,
            consensus_timeout_commit,
        );

        let finalized_1 = finalize(
            templates,
            chain_id_prefix,
            genesis_time,
            consensus_timeout_commit,
        );

        pretty_assertions::assert_eq!(finalized_0, finalized_1);
    }
}
