use std::path::PathBuf;
use std::str::FromStr;

use eyre::eyre;
use namada_core::address::Address;
use namada_node::shell::testing::client::run;
use namada_node::shell::testing::node::MockNode;
use namada_node::shell::testing::utils::{Bin, CapturedOutput};
use namada_sdk::key::common;

use crate::e2e::setup::constants::{FRANK, FRANK_KEY};
use crate::strings::TX_APPLIED_SUCCESS;

/// Query the wallet to get an address from a given alias.
pub fn find_address(
    node: &MockNode,
    alias: impl AsRef<str>,
) -> eyre::Result<Address> {
    let captured = CapturedOutput::of(|| {
        run(
            node,
            Bin::Wallet,
            vec!["find", "--addr", "--alias", alias.as_ref()],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("Found transparent address:"));
    let matched = captured.matches("\".*\": .*").unwrap();
    let address_str = strip_trailing_newline(matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let address = Address::from_str(address_str).map_err(|e| {
        eyre!(format!(
            "Address: {} parsed from {}, Error: {}",
            address_str, matched, e,
        ))
    })?;
    println!("Found {}", address);
    Ok(address)
}

pub fn find_keypair(
    node: &MockNode,
    alias: impl AsRef<str>,
) -> eyre::Result<common::SecretKey> {
    let captured = CapturedOutput::of(|| {
        run(
            node,
            Bin::Wallet,
            vec![
                "find",
                "--keys",
                "--alias",
                alias.as_ref(),
                "--decrypt",
                "--unsafe-show-secret",
            ],
        )
    });
    assert!(captured.result.is_ok());
    let matched = captured.matches("Public key: .*").unwrap();
    let pk = strip_trailing_newline(matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let matched = captured.matches("Secret key: .*").unwrap();
    let sk = strip_trailing_newline(matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let key = format!("{}{}", sk, pk);
    common::SecretKey::from_str(sk).map_err(|e| {
        eyre!(format!(
            "Key: {} parsed from {}, Error: {}",
            key, matched, e
        ))
    })
}

// Make a temporary account with the given balance and return its key. This
// function is useful because the integration tests can no longer assume that
// the secret keys are accessible.
pub fn make_temp_account(
    node: &MockNode,
    ledger_address: &str,
    key_alias: &'static str,
    token: &str,
    amount: u64,
) -> eyre::Result<(&'static str, common::SecretKey)> {
    // a. Generate a new key for an implicit account.
    run(
        node,
        Bin::Wallet,
        vec![
            "gen",
            "--alias",
            key_alias,
            "--unsafe-dont-encrypt",
            "--raw",
        ],
    )?;
    // b. Reveal the public key associated with an address
    let reveal_args = vec![
        "reveal-pk",
        "--public-key",
        key_alias,
        "--gas-payer",
        FRANK_KEY,
        "--node",
        ledger_address,
    ];
    let captured = CapturedOutput::of(|| run(node, Bin::Client, reveal_args));
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    // c. Send some funds to the implicit account.
    let amount = amount.to_string();
    let credit_args = vec![
        "transparent-transfer",
        "--source",
        FRANK,
        "--target",
        key_alias,
        "--token",
        token,
        "--amount",
        &amount,
        "--signing-keys",
        FRANK_KEY,
        "--node",
        ledger_address,
    ];
    let captured = CapturedOutput::of(|| run(node, Bin::Client, credit_args));
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    // d. Obtain the key pair associated with the new address
    let keypair = find_keypair(node, key_alias)?;
    Ok((key_alias, keypair))
}

fn strip_trailing_newline(input: &str) -> &str {
    input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(input)
}

pub fn prepare_steward_commission_update_data(
    test_dir: &std::path::Path,
    data: impl serde::Serialize,
) -> PathBuf {
    let valid_commission_json_path = test_dir.join("commission.json");
    write_json_file(valid_commission_json_path.as_path(), &data);
    valid_commission_json_path
}

fn write_json_file<T>(proposal_path: &std::path::Path, proposal_content: T)
where
    T: serde::Serialize,
{
    let intent_writer = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(proposal_path)
        .unwrap();

    serde_json::to_writer(intent_writer, &proposal_content).unwrap();
}
