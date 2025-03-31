use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::prelude::{BASE64_STANDARD, Engine};
use color_eyre::owo_colors::OwoColorize;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use itertools::Either;
use namada_sdk::address::{Address, ImplicitAddress};
use namada_sdk::args::DeviceTransport;
use namada_sdk::borsh::BorshSerializeExt;
use namada_sdk::chain::ChainId;
use namada_sdk::dec::Dec;
use namada_sdk::ibc::trace::ibc_token;
use namada_sdk::key::*;
use namada_sdk::signing::OfflineSignatures;
use namada_sdk::string_encoding::StringEncoded;
use namada_sdk::token;
use namada_sdk::tx::Tx;
use namada_sdk::uint::Uint;
use namada_sdk::wallet::{LoadStoreError, Wallet, alias};
use namada_vm::validate_untrusted_wasm;
use prost::bytes::Bytes;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::cli::args;
use crate::cli::context::wasm_dir_from_env_or;
use crate::config::genesis::chain::DeriveEstablishedAddress;
use crate::config::genesis::transactions::{
    UnsignedTransactions, sign_delegation_bond_tx, sign_validator_account_tx,
};
use crate::config::genesis::{AddrOrPk, GenesisAddress};
use crate::config::global::GlobalConfig;
use crate::config::{self, TendermintMode, genesis, get_default_namada_folder};
use crate::tendermint::node::Id as TendermintNodeId;
use crate::wallet::{CliWalletUtils, pre_genesis};
use crate::{tendermint_node, wasm_loader};

pub const NET_ACCOUNTS_DIR: &str = "setup";
pub const NET_OTHER_ACCOUNTS_DIR: &str = "other";
pub const ENV_VAR_NETWORK_CONFIGS_DIR: &str = "NAMADA_NETWORK_CONFIGS_DIR";
/// Github URL prefix of released Namada network configs
pub const ENV_VAR_NETWORK_CONFIGS_SERVER: &str =
    "NAMADA_NETWORK_CONFIGS_SERVER";
const DEFAULT_NETWORK_CONFIGS_SERVER: &str =
    "https://github.com/heliaxdev/anoma-network-config/releases/download";

/// We do pre-genesis validator set up in this directory
pub const PRE_GENESIS_DIR: &str = "pre-genesis";

/// Configure Namada to join an existing network. The chain must be released in
/// the <https://github.com/heliaxdev/anoma-network-config> repository.
pub async fn join_network(
    global_args: args::Global,
    args::JoinNetwork {
        chain_id,
        genesis_validator,
        pre_genesis_path,
        allow_duplicate_ip,
        add_persistent_peers,
    }: args::JoinNetwork,
) {
    use tokio::fs;

    let base_dir = global_args.base_dir;

    // If the base-dir doesn't exist yet, create it
    if let Err(err) = fs::canonicalize(&base_dir).await {
        if err.kind() == std::io::ErrorKind::NotFound {
            fs::create_dir_all(&base_dir).await.unwrap();
        }
    } else {
        // If the base-dir exists, check if it's already got this chain ID
        if fs::canonicalize(base_dir.join(chain_id.as_str()))
            .await
            .is_ok()
        {
            eprintln!("The chain directory for {} already exists.", chain_id);
            safe_exit(1);
        }
    }
    let base_dir_full = fs::canonicalize(&base_dir).await.unwrap();
    let chain_dir = base_dir_full.join(chain_id.as_str());

    let validator_alias_and_dir = pre_genesis_path
        .and_then(|path| {
            let alias = path.components().next_back()?;
            match alias {
                std::path::Component::Normal(alias) => {
                    let alias = alias.to_string_lossy().to_string();
                    println!(
                        "Using {alias} parsed from the given \
                         --pre-genesis-path"
                    );
                    Some((alias, path))
                }
                _ => None,
            }
        })
        .or_else(|| {
            genesis_validator.as_ref().map(|alias| {
                (
                    alias.clone(),
                    validator_pre_genesis_dir(&base_dir_full, alias),
                )
            })
        });

    // Pre-load the validator pre-genesis wallet and its keys to validate that
    // everything is in place before downloading the network archive
    let validator_alias_and_pre_genesis_wallet = validator_alias_and_dir
        .as_ref()
        .map(|(validator_alias, pre_genesis_dir)| {
            (
                alias::Alias::from(validator_alias),
                pre_genesis::load(pre_genesis_dir).unwrap_or_else(|err| {
                    eprintln!(
                        "Error loading validator pre-genesis wallet {err}",
                    );
                    safe_exit(1)
                }),
            )
        });

    let release_filename = format!("{}.tar.gz", chain_id);
    let net_config = if let Some(configs_dir) = network_configs_dir() {
        fs::read(PathBuf::from(&configs_dir).join(release_filename))
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "Network config not found or couldn't be read from dir \
                     \"{configs_dir}\" set by an env var \
                     {ENV_VAR_NETWORK_CONFIGS_DIR}. Error: {err}."
                )
            })
    } else {
        let release_url = format!(
            "{}/{}",
            network_configs_url_prefix(&chain_id),
            release_filename
        );

        // Read or download the release archive
        println!("Downloading config release from {} ...", release_url);
        let release: Bytes = match download_file(release_url).await {
            Ok(contents) => contents,
            Err(error) => {
                eprintln!("Error downloading release: {}", error);
                safe_exit(1);
            }
        };
        release.to_vec()
    };

    // Decode and unpack the archive
    let decoder = GzDecoder::new(&net_config[..]);
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(&base_dir_full).unwrap();
    _ = archive;

    // Read the genesis files
    let genesis = genesis::chain::Finalized::read_toml_files(&chain_dir)
        .unwrap_or_else(|err| {
            eprintln!(
                "Failed to read genesis TOML files from {} with {err}.",
                chain_dir.to_string_lossy()
            );
            safe_exit(1)
        });

    // Try to find validator data when using a pre-genesis validator
    let validator_keys = validator_alias_and_pre_genesis_wallet.as_ref().map(
        |(_alias, wallet)| {
            let tendermint_node_key: common::SecretKey =
                wallet.tendermint_node_key.clone();
            let consensus_key: common::SecretKey = wallet.consensus_key.clone();
            (tendermint_node_key, consensus_key)
        },
    );
    let is_validator = validator_alias_and_pre_genesis_wallet.is_some();
    let node_mode = if is_validator {
        TendermintMode::Validator
    } else {
        TendermintMode::Full
    };

    // Derive config from genesis
    let mut config = genesis.derive_config(
        &chain_dir,
        node_mode,
        validator_keys.as_ref().map(|(sk, _)| sk.ref_to()).as_ref(),
        allow_duplicate_ip,
        add_persistent_peers,
    );

    // Try to load pre-genesis wallet, if any
    let pre_genesis_wallet_path = base_dir.join(PRE_GENESIS_DIR);
    let pre_genesis_wallet =
        if let Ok(wallet) = crate::wallet::load(&pre_genesis_wallet_path) {
            Some(wallet)
        } else {
            validator_alias_and_dir
                .as_ref()
                .and_then(|(_, path)| crate::wallet::load(path).ok())
        };

    // Derive wallet from genesis
    let wallet = genesis.derive_wallet(
        &chain_dir,
        pre_genesis_wallet,
        validator_alias_and_pre_genesis_wallet,
    );

    // Setup the node for a genesis validator, if used
    if let Some((tendermint_node_key, consensus_key)) = validator_keys {
        println!(
            "Setting up validator keys in CometBFT. Consensus key: {}.",
            consensus_key.to_public()
        );
        let tm_home_dir = chain_dir.join(config::COMETBFT_DIR);
        // Write consensus key to tendermint home
        tendermint_node::write_validator_key(&tm_home_dir, &consensus_key)
            .unwrap();

        // Write tendermint node key
        write_tendermint_node_key(&tm_home_dir, tendermint_node_key);

        // Pre-initialize tendermint validator state
        tendermint_node::write_validator_state(&tm_home_dir).unwrap();
    } else {
        println!(
            "No validator keys are being used. Make sure you didn't forget to \
             specify `--genesis-validator`?"
        );
    }

    // Move wasm-dir and update config if it's non-default
    if let Some(wasm_dir) = wasm_dir_from_env_or(global_args.wasm_dir.as_ref())
    {
        let wasm_dir_full = chain_dir.join(wasm_dir);

        tokio::fs::rename(
            base_dir_full
                .join(chain_id.as_str())
                .join(config::DEFAULT_WASM_DIR),
            &wasm_dir_full,
        )
        .await
        .unwrap();

        config.wasm_dir = wasm_dir_full;
    }

    // Validate the wasm artifacts checksums
    validate_wasm_artifacts_aux(&chain_id, &chain_dir.join(&config.wasm_dir))
        .await;

    // Save the config and the wallet
    config.write(&base_dir, &chain_id, true).unwrap();
    crate::wallet::save(&wallet).unwrap();

    println!("Successfully configured for chain ID {chain_id}");
}

async fn validate_wasm_artifacts_aux(chain_id: &ChainId, wasm_dir: &Path) {
    println!("Validating wasms artifacts for chain ID {chain_id}...");
    wasm_loader::validate_wasm_artifacts(wasm_dir).await;
}

pub fn validate_wasm(args::ValidateWasm { code_path }: args::ValidateWasm) {
    let code = std::fs::read(code_path).unwrap();
    match validate_untrusted_wasm(code) {
        Ok(()) => println!("Wasm code is valid"),
        Err(e) => {
            eprintln!("Wasm code is invalid: {e}");
            safe_exit(1)
        }
    }
}

/// Length of a Tendermint Node ID in bytes
const TENDERMINT_NODE_ID_LENGTH: usize = 20;

/// Derive Tendermint node ID from public key
pub fn id_from_pk(pk: &common::PublicKey) -> TendermintNodeId {
    let mut bytes = [0u8; TENDERMINT_NODE_ID_LENGTH];

    match pk {
        common::PublicKey::Ed25519(_) => {
            let _pk: ed25519::PublicKey = pk.try_to_pk().unwrap();
            let digest = Sha256::digest(_pk.serialize_to_vec().as_slice());
            bytes.copy_from_slice(&digest[..TENDERMINT_NODE_ID_LENGTH]);
        }
        common::PublicKey::Secp256k1(_) => {
            let _pk: secp256k1::PublicKey = pk.try_to_pk().unwrap();
            let digest = Sha256::digest(_pk.serialize_to_vec().as_slice());
            bytes.copy_from_slice(&digest[..TENDERMINT_NODE_ID_LENGTH]);
        }
    }
    TendermintNodeId::new(bytes)
}

/// Initialize a new test network from the given configuration.
pub fn init_network(
    global_args: args::Global,
    args::InitNetwork {
        templates_path,
        wasm_checksums_path,
        chain_id_prefix,
        genesis_time,
        consensus_timeout_commit,
        archive_dir,
    }: args::InitNetwork,
) -> PathBuf {
    let base_dir = tempfile::tempdir().unwrap();

    // Load and validate the templates
    let templates = genesis::templates::load_and_validate(&templates_path)
        .unwrap_or_else(|| {
            eprintln!("Invalid templates, aborting.");
            safe_exit(1)
        });

    // In addition to standard templates validation, check that there is at
    // least one validator account.
    if !templates.transactions.has_at_least_one_validator() {
        eprintln!("No validator genesis transaction found, aborting.");
        safe_exit(1)
    }

    // Also check that at least one validator account has positive voting power.
    let tm_votes_per_token = templates.parameters.pos_params.tm_votes_per_token;
    if !templates
        .transactions
        .has_validator_with_positive_voting_power(tm_votes_per_token)
    {
        let min_stake = token::Amount::from_uint(
            if tm_votes_per_token > Dec::from(1) {
                Uint::one()
            } else {
                (Dec::from(1).checked_div(tm_votes_per_token).unwrap())
                    .ceil()
                    .unwrap()
                    .abs()
            },
            token::NATIVE_MAX_DECIMAL_PLACES,
        )
        .unwrap();
        eprintln!(
            "No validator with positive voting power, aborting. The minimum \
             staked tokens amount required to run the network is {}, because \
             there are {tm_votes_per_token} votes per NAMNAM tokens.",
            min_stake.to_string_native(),
        );
        safe_exit(1)
    }

    // Finalize the genesis config to derive the chain ID
    let genesis = genesis::chain::finalize(
        templates,
        chain_id_prefix,
        genesis_time,
        consensus_timeout_commit,
    );

    let chain_id = &genesis.metadata.chain_id;
    println!("Derived chain ID: {chain_id}");

    // Check that chain dir is empty
    let chain_dir = base_dir.path().join(chain_id.as_str());
    fs::create_dir_all(&chain_dir).unwrap();

    // Write the finalized genesis config to the chain dir
    genesis.write_toml_files(&chain_dir).unwrap_or_else(|err| {
        eprintln!(
            "Failed to write finalized genesis TOML files to {} with {err}.",
            chain_dir.to_string_lossy()
        );
        safe_exit(1)
    });

    // Write the global config setting the default chain ID
    let global_config = GlobalConfig::new(chain_id.clone());
    global_config.write(base_dir.path()).unwrap();

    // Copy the WASM checksums
    let wasm_dir_full = chain_dir.join(config::DEFAULT_WASM_DIR);
    fs::create_dir_all(&wasm_dir_full).unwrap();
    fs::copy(
        wasm_checksums_path,
        wasm_dir_full.join(config::DEFAULT_WASM_CHECKSUMS_FILE),
    )
    .unwrap();

    // Try to copy the built WASM, if they're present with the checksums
    let checksums = wasm_loader::Checksums::read_checksums(&wasm_dir_full)
        .unwrap_or_else(|_| safe_exit(1));
    let base_wasm_path = global_args.wasm_dir.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap()
            .join(crate::config::DEFAULT_WASM_DIR)
    });
    for (_, full_name) in checksums.0 {
        // try to copy built file from the Namada WASM root dir
        let file = base_wasm_path.join(&full_name);
        if !file.exists() {
            println!(
                "Skipping nonexistent wasm artifact: {}",
                file.to_string_lossy()
            );
            continue;
        }
        fs::copy(file, wasm_dir_full.join(&full_name)).unwrap();
    }

    // Create release tarball
    let mut release = tar::Builder::new(Vec::new());
    release
        .append_dir_all(PathBuf::from(chain_id.as_str()), &chain_dir)
        .unwrap();
    let global_config_path = GlobalConfig::file_path(base_dir.path());
    let release_global_config_path = GlobalConfig::file_path("");
    release
        .append_path_with_name(global_config_path, release_global_config_path)
        .unwrap();

    // Gzip tar release and write to file
    let release_file = archive_dir
        .unwrap_or_else(|| env::current_dir().unwrap())
        .join(format!("{}.tar.gz", chain_id));
    let compressed_file = File::create(&release_file).unwrap();
    let mut encoder = GzEncoder::new(compressed_file, Compression::default());
    encoder.write_all(&release.into_inner().unwrap()).unwrap();
    encoder.finish().unwrap();
    println!(
        "Release archive created at {}",
        release_file.to_string_lossy()
    );

    release_file
}

pub fn pk_to_tm_address(
    _global_args: args::Global,
    args::PkToTmAddress { public_key }: args::PkToTmAddress,
) {
    let tm_addr = tm_consensus_key_raw_hash(&public_key);
    println!("{tm_addr}");
}

pub fn default_base_dir(
    _global_args: args::Global,
    _args: args::DefaultBaseDir,
) {
    println!(
        "{}",
        get_default_namada_folder().to_str().expect(
            "expected a default namada folder to be possible to determine"
        )
    );
}

/// Derive and print all established addresses from the provided
/// genesis txs toml file.
pub fn derive_genesis_addresses(
    global_args: args::Global,
    args: args::DeriveGenesisAddresses,
) {
    let maybe_pre_genesis_wallet =
        try_load_pre_genesis_wallet(&global_args.base_dir)
            .ok()
            .map(|(wallet, _)| wallet);
    let contents =
        fs::read_to_string(&args.genesis_txs_path).unwrap_or_else(|err| {
            eprintln!(
                "Unable to read from file {}. Failed with error {err}.",
                args.genesis_txs_path.to_string_lossy()
            );
            safe_exit(1)
        });
    let (estbd_txs, validator_addrs) =
        toml::from_str::<UnsignedTransactions>(&contents)
            .ok()
            .map(|txs| {
                (
                    txs.established_account.unwrap_or_default(),
                    txs.validator_account
                        .unwrap_or_default()
                        .into_iter()
                        .map(|acct| acct.address)
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap_or_else(|| {
                let genesis_txs = genesis::templates::read_transactions(
                    &args.genesis_txs_path,
                )
                .unwrap();
                (
                    genesis_txs.established_account.unwrap_or_default(),
                    genesis_txs
                        .validator_account
                        .unwrap_or_default()
                        .into_iter()
                        .map(|acct| acct.data.address)
                        .collect(),
                )
            });

    println!("{}", "Established account txs:".underline().bold());
    for tx in &estbd_txs {
        println!();
        println!(
            "{} {}",
            "Address:".bold().bright_green(),
            tx.derive_address()
        );

        println!("{}", "Public key(s):".bold().bright_green());
        for (ix, pk) in tx.public_keys.iter().enumerate() {
            println!("    {}. {}", ix, pk);

            let maybe_alias =
                maybe_pre_genesis_wallet.as_ref().and_then(|wallet| {
                    let implicit_address = (&pk.raw).into();
                    wallet.find_alias(&implicit_address)
                });

            if let Some(alias) = maybe_alias {
                println!("{} {alias}", "Wallet alias:".bold().bright_green());
            }
        }
    }
    if estbd_txs.is_empty() {
        println!();
        println!("{}", "<nil>".dimmed());
    }
    println!();

    println!("{}", "Validator account txs:".underline().bold());
    for addr in &validator_addrs {
        println!();
        println!("{} {}", "Address:".bold().bright_green(), addr.raw);
    }
    if validator_addrs.is_empty() {
        println!();
        println!("{}", "<nil>".dimmed());
    }
}

/// Initialize a genesis established account.
/// key into a special "pre-genesis" wallet.
pub fn init_genesis_established_account(
    global_args: args::Global,
    args: args::InitGenesisEstablishedAccount,
) {
    let (pre_genesis_wallet, _) =
        load_pre_genesis_wallet_or_exit(&global_args.base_dir);

    let public_keys: Vec<_> = args
        .wallet_aliases
        .iter()
        .map(|alias| {
            let pk = pre_genesis_wallet.find_public_key(alias).unwrap_or_else(
                |err| {
                    eprintln!(
                        "Failed to look-up `{alias}` in the pre-genesis \
                         wallet: {err}",
                    );
                    safe_exit(1)
                },
            );
            StringEncoded::new(pk)
        })
        .collect();

    let (address, txs) = genesis::transactions::init_established_account(
        args.vp,
        public_keys,
        args.threshold,
    );
    let toml_path = args.output_path;
    let toml_path_str = toml_path.to_string_lossy();

    let genesis_part = toml::to_string(&txs).unwrap();
    fs::write(&toml_path, genesis_part).unwrap_or_else(|err| {
        eprintln!(
            "Couldn't write pre-genesis transactions file to {toml_path_str}. \
             Failed with: {err}",
        );
        safe_exit(1)
    });

    println!(
        "{}: {}\n",
        "Derived established account address".bold(),
        address.green(),
    );
    println!(
        "{}: keep a note of this address, especially if you plan to use it \
         for a validator account in the future!\n",
        "IMPORTANT".bold().yellow()
    );
    println!("{}: {toml_path_str}\n", "Wrote genesis tx to".bold());
}

/// Bond to a validator at pre-genesis.
pub fn genesis_bond(global_args: args::Global, args: args::GenesisBond) {
    let args::GenesisBond {
        source,
        validator,
        bond_amount,
        output: toml_path,
    } = args;

    let (wallet, _wallet_file) =
        load_pre_genesis_wallet_or_exit(&global_args.base_dir);
    let source = match source {
        AddrOrPk::Address(addr) => match &addr {
            Address::Established(established) => {
                GenesisAddress::EstablishedAddress(established.clone())
            }
            Address::Implicit(internal) => {
                match wallet.find_public_key_from_implicit_addr(internal) {
                    Ok(pk) => GenesisAddress::PublicKey(StringEncoded::new(pk)),
                    Err(err) => {
                        eprintln!(
                            "Couldn't find the PK associated with the given \
                             implicit address {addr} in the wallet: {err}"
                        );
                        safe_exit(1)
                    }
                }
            }
            Address::Internal(_) => {
                eprintln!("Unexpected internal address as bond source");
                safe_exit(1);
            }
        },
        AddrOrPk::PublicKey(pk) => GenesisAddress::PublicKey(pk),
    };
    let txs = genesis::transactions::init_bond(source, validator, bond_amount);

    let toml_path_str = toml_path.to_string_lossy();

    let genesis_part = toml::to_string(&txs).unwrap();
    fs::write(&toml_path, genesis_part).unwrap_or_else(|err| {
        eprintln!(
            "Couldn't write pre-genesis transactions file to {toml_path_str}. \
             Failed with: {err}",
        );
        safe_exit(1)
    });

    println!("{}: {toml_path_str}", "Wrote genesis tx to".bold());
}

/// Initialize genesis validator's address, consensus key and validator account
/// key into a special "pre-genesis" wallet.
pub fn init_genesis_validator(
    global_args: args::Global,
    args::InitGenesisValidator {
        alias,
        commission_rate,
        max_commission_rate_change,
        net_address,
        unsafe_dont_encrypt,
        key_scheme,
        self_bond_amount,
        email,
        description,
        website,
        discord_handle,
        avatar,
        name,
        tx_path,
        address,
    }: args::InitGenesisValidator,
) {
    let contents = fs::read_to_string(&tx_path).unwrap_or_else(|err| {
        eprintln!(
            "Unable to read from file {}. Failed with error {err}.",
            tx_path.to_string_lossy()
        );
        safe_exit(1)
    });
    let prev_txs: UnsignedTransactions = toml::from_str(&contents).unwrap();
    if prev_txs
        .established_account
        .as_ref()
        .and_then(|accts| {
            accts
                .iter()
                .find(|acct| acct.derive_established_address() == address)
        })
        .is_none()
    {
        eprintln!(
            "The provided file did not contain an established account tx with \
             the provided address {}",
            address
        );
        safe_exit(1);
    }

    // Validate the commission rate data
    if commission_rate > Dec::one() {
        eprintln!("The validator commission rate must not exceed 1.0 or 100%");
        safe_exit(1)
    }
    if max_commission_rate_change > Dec::one() {
        eprintln!(
            "The validator maximum change in commission rate per epoch must \
             not exceed 1.0 or 100%"
        );
        safe_exit(1)
    }
    // Validate the email
    if email.is_empty() {
        eprintln!("The validator email must not be an empty string");
        safe_exit(1)
    }
    let pre_genesis_dir =
        validator_pre_genesis_dir(&global_args.base_dir, &alias);
    println!("Generating validator keys...");
    let validator_wallet = pre_genesis::gen_and_store(
        key_scheme,
        unsafe_dont_encrypt,
        &pre_genesis_dir,
    )
    .unwrap_or_else(|err| {
        eprintln!(
            "Unable to generate the validator pre-genesis wallet: {}",
            err
        );
        safe_exit(1)
    });
    println!(
        "The validator's keys were stored in the wallet at {}",
        pre_genesis::validator_file_name(&pre_genesis_dir).to_string_lossy()
    );

    let (address, mut transactions) = genesis::transactions::init_validator(
        genesis::transactions::GenesisValidatorData {
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
        },
        &validator_wallet,
    );
    let toml_path = tx_path;
    let toml_path_str = toml_path.to_string_lossy();
    // append new transactions to the previous txs from the provided file.
    transactions.established_account = prev_txs.established_account;
    transactions
        .validator_account
        .as_mut()
        .unwrap()
        .append(&mut prev_txs.validator_account.unwrap_or_default());
    transactions
        .bond
        .as_mut()
        .unwrap()
        .append(&mut prev_txs.bond.unwrap_or_default());

    let genesis_part = toml::to_string(&transactions).unwrap();
    fs::write(&toml_path, genesis_part).unwrap_or_else(|err| {
        eprintln!(
            "Couldn't write pre-genesis transactions file to {toml_path_str}. \
             Failed with: {err}",
        );
        safe_exit(1)
    });

    println!(
        "{}: {}",
        "Validator account address".bold(),
        address.green()
    );
    println!("{}: {toml_path_str}", "Wrote genesis tx to".bold());
}

/// Try to load a pre-genesis wallet or return nothing,
/// if it cannot be found.
pub fn try_load_pre_genesis_wallet(
    base_dir: &Path,
) -> Result<(Wallet<CliWalletUtils>, PathBuf), LoadStoreError> {
    let pre_genesis_dir = base_dir.join(PRE_GENESIS_DIR);

    crate::wallet::load(&pre_genesis_dir).map(|wallet| {
        let wallet_file = crate::wallet::wallet_file(&pre_genesis_dir);
        (wallet, wallet_file)
    })
}

/// Try to load a pre-genesis wallet or terminate if it cannot be found.
pub fn load_pre_genesis_wallet_or_exit(
    base_dir: &Path,
) -> (Wallet<CliWalletUtils>, PathBuf) {
    match try_load_pre_genesis_wallet(base_dir) {
        Ok(wallet) => wallet,
        Err(e) => {
            eprintln!("Error loading the wallet: {e}");
            safe_exit(1)
        }
    }
}
async fn download_file(url: impl AsRef<str>) -> reqwest::Result<Bytes> {
    let url = url.as_ref();
    let response = reqwest::get(url).await?;
    response.error_for_status_ref()?;
    let contents = response.bytes().await?;
    Ok(contents)
}

fn network_configs_url_prefix(chain_id: &ChainId) -> String {
    std::env::var(ENV_VAR_NETWORK_CONFIGS_SERVER).unwrap_or_else(|_| {
        format!("{DEFAULT_NETWORK_CONFIGS_SERVER}/{chain_id}")
    })
}

fn network_configs_dir() -> Option<String> {
    std::env::var(ENV_VAR_NETWORK_CONFIGS_DIR).ok()
}

/// Write the node key into tendermint config dir.
pub fn write_tendermint_node_key(
    tm_home_dir: &Path,
    node_sk: common::SecretKey,
) -> common::PublicKey {
    let node_pk: common::PublicKey = node_sk.ref_to();

    // Convert and write the keypair into Tendermint node_key.json file.
    // Tendermint requires concatenating the private-public keys for ed25519
    // but does not for secp256k1.
    let (node_keypair, key_str) = match node_sk {
        common::SecretKey::Ed25519(sk) => (
            [sk.serialize_to_vec(), sk.ref_to().serialize_to_vec()].concat(),
            "Ed25519",
        ),
        common::SecretKey::Secp256k1(sk) => {
            (sk.serialize_to_vec(), "Secp256k1")
        }
    };

    let tm_node_keypair_json = json!({
        "priv_key": {
            "type": format!("tendermint/PrivKey{}",key_str),
            "value": BASE64_STANDARD.encode(node_keypair),
        }
    });
    let tm_config_dir = tm_home_dir.join("config");
    fs::create_dir_all(&tm_config_dir)
        .expect("Couldn't create validator directory");
    let node_key_path = tm_config_dir.join("node_key.json");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(node_key_path)
        .expect("Couldn't create validator node key file");
    serde_json::to_writer_pretty(file, &tm_node_keypair_json)
        .expect("Couldn't write validator node key file");
    node_pk
}

/// The default path to a validator pre-genesis txs file.
pub fn validator_pre_genesis_txs_file(pre_genesis_path: &Path) -> PathBuf {
    pre_genesis_path.join("transactions.toml")
}

/// The default validator pre-genesis directory
pub fn validator_pre_genesis_dir(base_dir: &Path, alias: &str) -> PathBuf {
    base_dir.join(PRE_GENESIS_DIR).join(alias)
}

/// Validate genesis templates. Exits process if invalid.
pub fn validate_genesis_templates(
    _global_args: args::Global,
    args::ValidateGenesisTemplates { path }: args::ValidateGenesisTemplates,
) {
    if genesis::templates::load_and_validate(&path).is_none() {
        safe_exit(1)
    }
}

async fn append_signature_to_signed_toml(
    input_txs: &Path,
    wallet: &RwLock<Wallet<CliWalletUtils>>,
    use_device: bool,
    device_transport: DeviceTransport,
) -> genesis::transactions::Transactions<genesis::templates::Unvalidated> {
    // Parse signed txs toml to append new signatures to
    let mut genesis_txs = genesis::templates::read_transactions(input_txs)
        .unwrap_or_else(|_| {
            eprintln!(
                "Unable to parse the TOML from path: {}",
                input_txs.to_string_lossy()
            );
            safe_exit(1)
        });
    // Sign bond txs and append signatures to toml file
    if let Some(txs) = genesis_txs.bond {
        let mut bonds = vec![];
        for tx in txs {
            bonds.push(
                sign_delegation_bond_tx(
                    tx,
                    wallet,
                    &genesis_txs.established_account,
                    use_device,
                    device_transport,
                )
                .await,
            );
        }
        genesis_txs.bond = Some(bonds);
    }
    // Sign validator txs and append signatures to toml file
    if let Some(txs) = genesis_txs.validator_account {
        let mut validator_accounts = vec![];
        for tx in txs {
            validator_accounts.push(
                sign_validator_account_tx(
                    Either::Right(tx),
                    wallet,
                    genesis_txs.established_account.as_ref().expect(
                        "Established account txs required when signing \
                         validator account txs",
                    ),
                    use_device,
                    device_transport,
                )
                .await,
            );
        }
        genesis_txs.validator_account = Some(validator_accounts);
    }
    genesis_txs
}

/// Sign genesis transactions.
pub async fn sign_genesis_tx(
    global_args: args::Global,
    args::SignGenesisTxs {
        path,
        output,
        validator_alias,
        use_device,
        device_transport,
    }: args::SignGenesisTxs,
) {
    let (wallet, _wallet_file) =
        load_pre_genesis_wallet_or_exit(&global_args.base_dir);
    let wallet_lock = RwLock::new(wallet);
    let maybe_pre_genesis_wallet = validator_alias.and_then(|alias| {
        let pre_genesis_dir =
            validator_pre_genesis_dir(&global_args.base_dir, &alias);
        pre_genesis::load(&pre_genesis_dir).ok()
    });
    let contents = fs::read_to_string(&path).unwrap_or_else(|err| {
        eprintln!(
            "Unable to read from file {}. Failed with {err}.",
            path.to_string_lossy()
        );
        safe_exit(1)
    });
    // Sign a subset of the input txs (the ones whose keys we own)
    let signed = if let Ok(unsigned) =
        genesis::transactions::parse_unsigned(&contents)
    {
        let signed = genesis::transactions::sign_txs(
            unsigned,
            &wallet_lock,
            maybe_pre_genesis_wallet.as_ref(),
            use_device,
            device_transport,
        )
        .await;
        if let Some(output_path) = output.as_ref() {
            // If the output path contains existing signed txs, we append
            // the newly signed txs to the file
            #[allow(clippy::disallowed_methods)]
            let mut prev_txs =
                genesis::templates::read_transactions(output_path)
                    .unwrap_or_default();
            prev_txs.merge(signed);
            prev_txs
        } else {
            signed
        }
    } else {
        // In case we fail to parse unsigned txs, we will attempt to
        // parse signed txs and append new signatures to the existing
        // toml file
        append_signature_to_signed_toml(
            &path,
            &wallet_lock,
            use_device,
            device_transport,
        )
        .await
    };
    match output {
        Some(output_path) => {
            let transactions = toml::to_string(&signed).unwrap();
            fs::write(&output_path, transactions).unwrap_or_else(|err| {
                eprintln!(
                    "Failed to write output to {} with {err}.",
                    output_path.to_string_lossy()
                );
                safe_exit(1);
            });
            println!(
                "Your public signed transactions TOML has been written to {}",
                output_path.to_string_lossy()
            );
        }
        None => {
            let transactions = toml::to_string(&signed).unwrap();
            println!("{transactions}");
        }
    }
}

/// Sign a transaction offline
pub async fn sign_offline(
    args::SignOffline {
        tx_path,
        secret_keys,
        owner,
        wrapper_signer,
        output_folder_path,
    }: args::SignOffline,
) {
    let tx_data = if let Ok(tx_data) = fs::read(&tx_path) {
        tx_data
    } else {
        eprintln!("Couldn't open file at {}", tx_path.display());
        safe_exit(1)
    };

    let tx = if let Ok(transaction) = Tx::try_from_json_bytes(tx_data.as_ref())
    {
        transaction
    } else {
        eprintln!("Couldn't decode the transaction.");
        safe_exit(1)
    };
    let raw_header_hash = tx.raw_header_hash();
    let header_hash = tx.header_hash();

    let OfflineSignatures {
        signatures,
        wrapper_signature,
    } = match namada_sdk::signing::generate_tx_signatures(
        tx,
        secret_keys,
        owner,
        wrapper_signer,
    )
    .await
    {
        Ok(sigs) => sigs,
        Err(e) => {
            eprintln!("Couldn't generate offline signatures: {}", e);
            safe_exit(1);
        }
    };

    for signature in &signatures {
        let filename = format!(
            "offline_signature_{}_{}.sig",
            raw_header_hash.to_string().to_lowercase(),
            signature.pubkey,
        );

        let signature_path = match &output_folder_path {
            Some(path) => path.join(filename).to_string_lossy().to_string(),
            None => filename,
        };

        let signature_file = File::create(&signature_path)
            .expect("Should be able to create signature file.");

        serde_json::to_writer_pretty(signature_file, &signature)
            .expect("Signature should be serializable.");

        println!(
            "Signature for {} serialized at {}",
            signature.pubkey, signature_path
        );
    }

    // Dump wrapper signature if requested
    if let Some(wrapper_signature) = wrapper_signature {
        let filename = format!(
            "offline_wrapper_signature_{}.sig",
            header_hash.to_string().to_lowercase()
        );
        let signature_path = match &output_folder_path {
            Some(path) => path.join(filename).to_string_lossy().to_string(),
            None => filename,
        };

        let signature_file = File::create(&signature_path)
            .expect("Should be able to create signature file.");

        serde_json::to_writer_pretty(signature_file, &wrapper_signature)
            .expect("Signature should be serializable.");

        println!("Wrapper signature serialized at {}", signature_path);
    }
}

/// Add a spinning wheel to a message for long running commands.
/// Can be turned off for E2E tests by setting the `REDUCED_CLI_PRINTING`
/// environment variable.
pub fn with_spinny_wheel<F, Out>(msg: &str, func: F) -> Out
where
    F: FnOnce() -> Out + Send + 'static,
    Out: Send + 'static,
{
    let task = std::thread::spawn(func);
    let spinny_wheel = "|/-\\";
    print!("{}", msg);
    _ = std::io::stdout().flush();
    for c in spinny_wheel.chars().cycle() {
        print!("{}", c);
        std::thread::sleep(std::time::Duration::from_secs(1));
        print!("{}", (8u8 as char));
        if task.is_finished() {
            break;
        }
    }
    println!();
    task.join().unwrap()
}

#[cfg(not(test))]
fn safe_exit(code: i32) -> ! {
    crate::cli::safe_exit(code)
}

#[cfg(test)]
fn safe_exit(code: i32) -> ! {
    panic!("Process exited unsuccessfully with error code: {}", code);
}

/// Derive the IBC token address on namada from the denom string
pub fn derive_ibc_token_address(
    args::DeriveIbcToken { ibc_denom }: args::DeriveIbcToken,
) {
    let token_address = ibc_token(&ibc_denom);
    println!("{token_address}");
}

/// Derive the implicit address from a raw public key
pub fn pubkey_to_address(
    args::PubKeyToAddr { public_key }: args::PubKeyToAddr,
) {
    let pkh = PublicKeyHash::from(&public_key);
    let addr = Address::Implicit(ImplicitAddress(pkh.clone()));
    println!("{addr}");
}
