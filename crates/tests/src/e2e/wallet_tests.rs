//! By default, these tests will run in release mode. This can be disabled
//! by setting environment variable `NAMADA_E2E_DEBUG=true`. For debugging,
//! you'll typically also want to set `RUST_BACKTRACE=1`, e.g.:
//!
//! ```ignore,shell
//! NAMADA_E2E_DEBUG=true RUST_BACKTRACE=1 cargo test e2e::wallet_tests -- --test-threads=1 --nocapture
//! ```
//!
//! To keep the temporary files created by a test, use env var
//! `NAMADA_E2E_KEEP_TEMP=true`.

use std::env;

use color_eyre::eyre::Result;

use super::setup;
use crate::e2e::setup::Bin;
use crate::run;
use crate::strings::{
    WALLET_FOUND_TRANSPARENT_KEYS, WALLET_HD_PASSPHRASE_CONFIRMATION_PROMPT,
    WALLET_HD_PASSPHRASE_PROMPT,
};

/// Test wallet key commands with an encrypted key:
/// 1. key gen
/// 2. key find
/// 3. key list
#[test]
fn wallet_encrypted_key_cmds() -> Result<()> {
    let test = setup::single_node_net()?;
    let key_alias = "Test_Key_1";
    let password = "VeRySeCuR3";

    // 1. key gen
    let mut cmd = run!(
        test,
        Bin::Wallet,
        &["gen", "--alias", key_alias, "--bip39-passphrase"],
        Some(20),
    )?;

    cmd.exp_string("Enter your encryption password:")?;
    cmd.send_line(password)?;
    cmd.exp_string("Enter same passphrase again: ")?;
    cmd.send_line(password)?;
    cmd.exp_string(WALLET_HD_PASSPHRASE_PROMPT)?;
    cmd.send_line("test")?;
    cmd.exp_string(WALLET_HD_PASSPHRASE_CONFIRMATION_PROMPT)?;
    cmd.send_line("test")?;
    cmd.exp_string(&format!(
        "Successfully added a key and an address with alias: \"{}\"",
        key_alias.to_lowercase()
    ))?;

    // 2. key find
    let mut cmd = run!(
        test,
        Bin::Wallet,
        &["find", "--keys", "--alias", key_alias, "--decrypt"],
        Some(20),
    )?;

    cmd.exp_string(WALLET_FOUND_TRANSPARENT_KEYS)?;
    cmd.exp_string(&format!(
        "  Alias \"{}\" (encrypted):",
        key_alias.to_lowercase()
    ))?;
    cmd.exp_string("    Public key hash:")?;
    cmd.exp_string("    Public key:")?;
    cmd.exp_string("Enter your decryption password")?;
    cmd.send_line(password)?;

    // 3. key list
    let mut cmd = run!(test, Bin::Wallet, &["list", "--keys"], Some(20))?;
    cmd.exp_string(&format!(
        "Alias \"{}\" (encrypted):",
        key_alias.to_lowercase()
    ))?;

    Ok(())
}

/// Test wallet key commands with an encrypted key supplied via ENV:
/// 1. key gen
/// 2. key find
/// 3. key list
#[test]
fn wallet_encrypted_key_cmds_env_var() -> Result<()> {
    let test = setup::single_node_net()?;
    let key_alias = "Test_Key_1";
    let password = "VeRySeCuR3";

    unsafe { env::set_var("NAMADA_WALLET_PASSWORD", password) };

    // 1. key gen
    let mut cmd =
        run!(test, Bin::Wallet, &["gen", "--alias", key_alias], Some(20),)?;

    cmd.exp_string(&format!(
        "Successfully added a key and an address with alias: \"{}\"",
        key_alias.to_lowercase()
    ))?;

    // 2. key find
    let mut cmd = run!(
        test,
        Bin::Wallet,
        &["find", "--keys", "--alias", key_alias, "--decrypt"],
        Some(20),
    )?;

    cmd.exp_string(WALLET_FOUND_TRANSPARENT_KEYS)?;
    cmd.exp_string(&format!(
        "  Alias \"{}\" (encrypted):",
        key_alias.to_lowercase()
    ))?;
    cmd.exp_string("    Public key hash:")?;
    cmd.exp_string("    Public key:")?;

    // 3. key list
    let mut cmd = run!(test, Bin::Wallet, &["list", "--keys"], Some(20))?;
    cmd.exp_string(&format!(
        "  Alias \"{}\" (encrypted):",
        key_alias.to_lowercase()
    ))?;

    Ok(())
}

/// Test wallet key commands with an unencrypted key:
/// 1. key gen
/// 2. key find
/// 3. key list
#[test]
fn wallet_unencrypted_key_cmds() -> Result<()> {
    let test = setup::single_node_net()?;
    let key_alias = "Test_Key_1";

    // 1. key gen
    let mut cmd = run!(
        test,
        Bin::Wallet,
        &["gen", "--alias", key_alias, "--unsafe-dont-encrypt"],
        Some(20),
    )?;

    cmd.exp_string(&format!(
        "Successfully added a key and an address with alias: \"{}\"",
        key_alias.to_lowercase()
    ))?;

    // 2. key find
    let mut cmd = run!(
        test,
        Bin::Wallet,
        &["find", "--keys", "--alias", key_alias],
        Some(20),
    )?;

    cmd.exp_string(WALLET_FOUND_TRANSPARENT_KEYS)?;
    cmd.exp_string(&format!(
        "  Alias \"{}\" (not encrypted):",
        key_alias.to_lowercase()
    ))?;
    cmd.exp_string("    Public key hash:")?;
    cmd.exp_string("    Public key:")?;

    // 3. key list
    let mut cmd = run!(test, Bin::Wallet, &["list", "--keys"], Some(20))?;
    cmd.exp_string(&format!(
        "  Alias \"{}\" (not encrypted):",
        key_alias.to_lowercase()
    ))?;

    Ok(())
}

/// Test wallet address commands:
/// 1. address gen
/// 2. address add
/// 3. address find
/// 4. address list
#[test]
fn wallet_address_cmds() -> Result<()> {
    let test = setup::single_node_net()?;
    let gen_address_alias = "Test_Address_1";
    let add_address_alias = "Test_Address_2";
    let add_address = "tnam1q82t25z5f9gmnv5sztyr8ht9tqhrw4u875qjhy56";

    // 1. address gen
    let mut cmd = run!(
        test,
        Bin::Wallet,
        &[
            "gen",
            "--alias",
            gen_address_alias,
            "--unsafe-dont-encrypt",
            "--raw"
        ],
        Some(20),
    )?;
    cmd.exp_string(&format!(
        "Successfully added a key and an address with alias: \"{}\"",
        gen_address_alias.to_lowercase()
    ))?;

    // 2. address add
    let mut cmd = run!(
        test,
        Bin::Wallet,
        &["add", "--value", add_address, "--alias", add_address_alias],
        Some(20),
    )?;
    cmd.exp_string(&format!(
        "Successfully added an address with alias: \"{}\"",
        add_address_alias.to_lowercase()
    ))?;

    // 3. address find
    let mut cmd = run!(
        test,
        Bin::Wallet,
        &["find", "--addr", "--alias", gen_address_alias],
        Some(20),
    )?;
    cmd.exp_string("Found transparent address:")?;

    // 4. address list
    let mut cmd = run!(test, Bin::Wallet, &["list", "--addr"], Some(20))?;

    cmd.exp_string("Known transparent addresses:")?;
    cmd.exp_string(&format!("\"{}\":", gen_address_alias.to_lowercase()))?;
    cmd.exp_string(&format!("\"{}\":", add_address_alias.to_lowercase()))?;

    Ok(())
}
