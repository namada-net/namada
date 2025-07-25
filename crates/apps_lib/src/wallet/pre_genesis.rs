use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fd_lock::RwLock;
use namada_sdk::key::SchemeType;
use namada_sdk::wallet::pre_genesis::{
    ReadError, ValidatorStore, ValidatorWallet,
};
use namada_sdk::wallet::{WalletIo, gen_key_to_store};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::wallet::store::gen_validator_keys;
use crate::wallet::{CliWalletUtils, read_and_confirm_encryption_password};

/// Validator pre-genesis wallet file name
const VALIDATOR_FILE_NAME: &str = "validator-wallet.toml";

/// Get the path to the validator pre-genesis wallet store.
pub fn validator_file_name(store_dir: impl AsRef<Path>) -> PathBuf {
    store_dir.as_ref().join(VALIDATOR_FILE_NAME)
}

/// Generate a new [`ValidatorWallet`] with required pre-genesis keys and
/// store it as TOML at the given path.
pub fn gen_and_store(
    scheme: SchemeType,
    unsafe_dont_encrypt: bool,
    store_dir: &Path,
) -> std::io::Result<ValidatorWallet> {
    let password = read_and_confirm_encryption_password(unsafe_dont_encrypt);
    let validator = r#gen(scheme, password);
    let data = validator.store.encode();
    let wallet_path = validator_file_name(store_dir);
    // Make sure the dir exists
    let wallet_dir = wallet_path.parent().unwrap();
    fs::create_dir_all(wallet_dir)?;
    // Write the file
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    let mut lock = RwLock::new(options.open(wallet_path)?);
    let mut guard = lock.write()?;
    guard.write_all(data.as_bytes())?;
    Ok(validator)
}

/// Try to load and decrypt keys, if encrypted, in a [`ValidatorWallet`]
/// from a TOML file.
pub fn load(store_dir: &Path) -> Result<ValidatorWallet, ReadError> {
    let wallet_file = validator_file_name(store_dir);
    let mut options = fs::OpenOptions::new();
    options.read(true).write(false);
    let lock = RwLock::new(options.open(&wallet_file).map_err(|err| {
        ReadError::ReadWallet(
            wallet_file.to_string_lossy().into_owned(),
            err.to_string(),
        )
    })?);
    let guard = lock.read().map_err(|err| {
        ReadError::ReadWallet(
            wallet_file.to_string_lossy().into_owned(),
            err.to_string(),
        )
    })?;
    let mut store = String::new();
    (&*guard).read_to_string(&mut store).map_err(|err| {
        ReadError::ReadWallet(
            store_dir.to_str().unwrap().into(),
            err.to_string(),
        )
    })?;
    let store = ValidatorStore::decode(&store).map_err(ReadError::Decode)?;

    let password = if store.consensus_key.is_encrypted() {
        Some(CliWalletUtils::read_password(false, Some("consensus key")))
    } else {
        None
    };

    let consensus_key = store.consensus_key.get::<CliWalletUtils>(
        true,
        password.clone(),
        Some("consensus key"),
    )?;
    let eth_cold_key = store.eth_cold_key.get::<CliWalletUtils>(
        true,
        password.clone(),
        Some("eth cold key"),
    )?;
    let eth_hot_key = store.validator_keys.eth_bridge_keypair.clone();
    let tendermint_node_key = store.tendermint_node_key.get::<CliWalletUtils>(
        true,
        password,
        Some("tendermint node key"),
    )?;

    Ok(ValidatorWallet {
        store,
        consensus_key,
        eth_cold_key,
        eth_hot_key,
        tendermint_node_key,
    })
}

/// Generate a new [`ValidatorWallet`] with required pre-genesis keys. Will
/// prompt for password when `!unsafe_dont_encrypt`.
fn r#gen(
    scheme: SchemeType,
    password: Option<Zeroizing<String>>,
) -> ValidatorWallet {
    let (consensus_key, consensus_sk) = gen_key_to_store(
        // Note that TM only allows ed25519 for consensus key
        SchemeType::Ed25519,
        password.clone(),
        &mut OsRng,
    );
    let (eth_cold_key, eth_cold_sk) =
        gen_key_to_store(SchemeType::Secp256k1, password.clone(), &mut OsRng);
    let (tendermint_node_key, tendermint_node_sk) = gen_key_to_store(
        // Note that TM only allows ed25519 for node IDs
        SchemeType::Ed25519,
        password,
        &mut OsRng,
    );
    let validator_keys = gen_validator_keys(None, None, scheme);
    let eth_hot_key = validator_keys.eth_bridge_keypair.clone();
    let store = ValidatorStore {
        consensus_key,
        eth_cold_key,
        tendermint_node_key,
        validator_keys,
    };
    ValidatorWallet {
        store,
        consensus_key: consensus_sk,
        eth_cold_key: eth_cold_sk,
        eth_hot_key,
        tendermint_node_key: tendermint_node_sk,
    }
}
