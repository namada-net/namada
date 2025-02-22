use std::collections::BTreeSet;
use std::fs;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use assert_matches::assert_matches;
use borsh::BorshDeserialize;
use color_eyre::eyre::Result;
use data_encoding::HEXLOWER;
use namada_apps_lib::wallet::defaults::{self, is_use_device};
use namada_core::chain::Epoch;
use namada_core::dec::Dec;
use namada_core::hash::Hash;
use namada_core::storage::{DbColFam, Key};
use namada_core::token::NATIVE_MAX_DECIMAL_PLACES;
use namada_node::shell::SnapshotSync;
use namada_node::shell::testing::client::run;
use namada_node::shell::testing::node::NodeResults;
use namada_node::shell::testing::utils::{Bin, CapturedOutput};
use namada_node::storage::DbSnapshot;
use namada_sdk::account::AccountPublicKeysMap;
use namada_sdk::borsh::BorshSerializeExt;
use namada_sdk::collections::HashMap;
use namada_sdk::error::TxSubmitError;
use namada_sdk::governance::cli::onchain::{PgfAction, PgfContinuous};
use namada_sdk::migrations;
use namada_sdk::proof_of_stake::parameters::MAX_VALIDATOR_METADATA_LEN;
use namada_sdk::queries::RPC;
use namada_sdk::token::{self, DenominatedAmount};
use namada_sdk::tx::{self, TX_TRANSFER_WASM, Tx, VP_USER_WASM};
use namada_test_utils::TestWasms;
use namada_tx_prelude::gov_storage::proposal::ContPGFTarget;
use test_log::test;

use crate::e2e::ledger_tests::prepare_proposal_data;
use crate::e2e::setup::apply_use_device;
use crate::e2e::setup::constants::{
    ALBERT, ALBERT_KEY, APFEL, BERTHA, BERTHA_KEY, BTC, CHRISTEL, CHRISTEL_KEY,
    DAEWON, DOT, ESTER, ETH, GOVERNANCE_ADDRESS, KARTOFFEL, NAM, PGF_ADDRESS,
    SCHNITZEL,
};
use crate::integration::helpers::{
    find_address, make_temp_account, prepare_steward_commission_update_data,
};
use crate::integration::setup;
use crate::strings::{
    TX_APPLIED_SUCCESS, TX_INSUFFICIENT_BALANCE, TX_REJECTED,
};
use crate::tendermint::abci::ApplySnapshotChunkResult;
use crate::tx::tx_host_env::gov_storage::proposal::{
    PGFInternalTarget, PGFTarget,
};
use crate::tx::tx_host_env::governance::cli::onchain::{
    PgfFunding, StewardsUpdate,
};
use crate::tx::tx_host_env::governance::pgf::cli::steward::Commission;

/// In this test we:
/// 1. Run the ledger node
/// 2. Submit a token transfer tx
/// 3. Submit a transaction to update an account's validity predicate
/// 4. Submit a custom tx
/// 5. Submit a tx to initialize a new account
/// 6. Submit a tx to withdraw from faucet account (requires PoW challenge
///    solution)
/// 7. Query token balance
/// 8. Query the raw bytes of a storage key
#[test]
fn ledger_txs_and_queries() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";

    let (node, _services) = setup::setup()?;
    let transfer = token::Transfer::default()
        .transfer(
            defaults::bertha_address(),
            defaults::albert_address(),
            node.native_token(),
            token::DenominatedAmount::new(
                token::Amount::native_whole(10),
                token::NATIVE_MAX_DECIMAL_PLACES.into(),
            ),
        )
        .unwrap()
        .serialize_to_vec();
    let tx_data_path = node.test_dir.path().join("tx.data");
    std::fs::write(&tx_data_path, transfer).unwrap();
    let tx_data_path = tx_data_path.to_string_lossy();

    let multisig_account =
        format!("{},{},{}", BERTHA_KEY, ALBERT_KEY, CHRISTEL_KEY);

    let txs_args = vec![
        // 2. Submit a token transfer tx (from an established account)
        apply_use_device(vec![
            "transparent-transfer",
            "--source",
            BERTHA,
            "--target",
            ALBERT,
            "--token",
            NAM,
            "--amount",
            "10.1",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ]),
        // Submit a token transfer tx (from an ed25519 implicit account)
        apply_use_device(vec![
            "transparent-transfer",
            "--source",
            DAEWON,
            "--target",
            ALBERT,
            "--token",
            NAM,
            "--amount",
            "10.1",
            "--signing-keys",
            DAEWON,
            "--node",
            &validator_one_rpc,
        ]),
        // Submit a token transfer tx (from a secp256k1 implicit account)
        apply_use_device(vec![
            "transparent-transfer",
            "--source",
            ESTER,
            "--target",
            ALBERT,
            "--token",
            NAM,
            "--amount",
            "10.1",
            "--signing-keys",
            ESTER,
            "--node",
            &validator_one_rpc,
        ]),
        // 3. Submit a transaction to update an account's validity
        // predicate
        apply_use_device(vec![
            "update-account",
            "--address",
            BERTHA,
            "--code-path",
            VP_USER_WASM,
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ]),
        // 4. Submit a custom tx
        apply_use_device(vec![
            "tx",
            "--code-path",
            TX_TRANSFER_WASM,
            "--data-path",
            &tx_data_path,
            "--owner",
            BERTHA,
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ]),
        // 5. Submit a tx to initialize a new account
        apply_use_device(vec![
            "init-account",
            "--public-keys",
            // Value obtained from `namada_sdk::key::ed25519::tests::gen_keypair`
            "tpknam1qpqfzxu3gt05jx2mvg82f4anf90psqerkwqhjey4zlqv0qfgwuvkzt5jhkp",
            "--threshold",
            "1",
            "--code-path",
            VP_USER_WASM,
            "--alias",
            "Test-Account",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ]),
        // 5. Submit a tx to initialize a new multisig account
        apply_use_device(vec![
            "init-account",
            "--public-keys",
            &multisig_account,
            "--threshold",
            "2",
            "--code-path",
            VP_USER_WASM,
            "--alias",
            "Test-Account-2",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ]),
    ];

    for tx_args in &txs_args {
        for &dry_run in &[true, false] {
            let tx_args = if dry_run && (tx_args[0] == "tx" || is_use_device())
            {
                continue;
            } else if dry_run {
                [tx_args.clone(), vec!["--dry-run-wrapper"]].concat()
            } else {
                tx_args.clone()
            };
            let captured =
                CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
            assert_matches!(captured.result, Ok(_));
            assert!(captured.contains(TX_APPLIED_SUCCESS));
        }
    }

    let query_args_and_expected_response = vec![
        // 7. Query token balance
        (
            vec![
                "balance",
                "--owner",
                BERTHA,
                "--token",
                NAM,
                "--node",
                &validator_one_rpc,
            ],
            // expect a decimal
            vec![r"nam: \d+(\.\d+)?"],
        ),
        // Test balance of tokens generated at genesis
        (
            vec![
                "balance",
                "--owner",
                ALBERT,
                "--token",
                APFEL,
                "--node",
                &validator_one_rpc,
            ],
            vec![r"apfel: \d+(\.\d+)?"],
        ),
        (
            vec![
                "balance",
                "--owner",
                ALBERT,
                "--token",
                BTC,
                "--node",
                &validator_one_rpc,
            ],
            vec![r"btc: \d+(\.\d+)?"],
        ),
        (
            vec![
                "balance",
                "--owner",
                ALBERT,
                "--token",
                DOT,
                "--node",
                &validator_one_rpc,
            ],
            vec![r"dot: \d+(\.\d+)?"],
        ),
        (
            vec![
                "balance",
                "--owner",
                ALBERT,
                "--token",
                ETH,
                "--node",
                &validator_one_rpc,
            ],
            vec![r"eth: \d+(\.\d+)?"],
        ),
        (
            vec![
                "balance",
                "--owner",
                ALBERT,
                "--token",
                KARTOFFEL,
                "--node",
                &validator_one_rpc,
            ],
            vec![r"kartoffel: \d+(\.\d+)?"],
        ),
        (
            vec![
                "balance",
                "--owner",
                ALBERT,
                "--token",
                SCHNITZEL,
                "--node",
                &validator_one_rpc,
            ],
            vec![r"schnitzel: \d+(\.\d+)?"],
        ),
        // Account query
        (
            vec![
                "query-account",
                "--owner",
                "Test-Account-2",
                "--node",
                &validator_one_rpc,
            ],
            vec!["Threshold: 2"],
        ),
    ];

    for (query_args, expected) in query_args_and_expected_response {
        // Run as a non-validator
        let captured =
            CapturedOutput::of(|| run(&node, Bin::Client, query_args));
        assert_matches!(captured.result, Ok(_));
        for pattern in expected {
            assert!(captured.contains(pattern));
        }
    }

    let christel = defaults::christel_address();
    let nam = node.native_token();
    // as setup in `genesis/e2e-tests-single-node.toml`
    let christel_balance = token::Amount::native_whole(2000000);
    let storage_key =
        token::storage_key::balance_key(&nam, &christel).to_string();
    let query_args_and_expected_response = vec![
        // 8. Query storage key and get hex-encoded raw bytes
        (
            vec![
                "query-bytes",
                "--storage-key",
                &storage_key,
                "--node",
                &validator_one_rpc,
            ],
            // expect hex encoded of borsh encoded bytes
            HEXLOWER.encode(&christel_balance.serialize_to_vec()),
        ),
    ];
    for (query_args, expected) in query_args_and_expected_response {
        let captured =
            CapturedOutput::of(|| run(&node, Bin::Client, query_args));
        assert_matches!(captured.result, Ok(_));
        assert!(captured.contains(&expected));
    }

    Ok(())
}

/// We test that we can dry-run transactions without
/// producing valid signatures. The gas estimation cost
/// should be the close to the same between dry-run and actual execution.
///
/// Steps:
///  1. Add a public key to the software wallet, but not its corresponding
///     secret. This mocks the scenario where a hardware wallet is being used
///  2. Dry-run a transaction from Bertha to the implicit account of the above
///     public key. Get the gas cost.
///  3. Actually perform the transfer and get the gas cost.
///  4. Check that the difference in gas cost between the dry-run and actual tx
///     is within 10% of the actual gas cost
///  5. Test that we dry-run a tx requiring a signature from the public key in
///     the first step without using a hardware wallet.
#[test]
fn test_dry_run_transaction() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // This is a public key whose secret counterpart is not in the software
    // wallet.
    const HARDWARE_WALLET_PK: &str =
        "tpknam1qpxpjvd9tm8jef9y07zsxhyhr2maeav06m9crh24ldkhtwrt7wj0y4gvem8";
    // The implicit address corresponding to HARDWARE_WALLET_PK
    const HARDWARE_WALLET_IMPLICIT: &str =
        "tnam1qqre7pwsjp9hgdfefehspujks0mdt3p90c7m3f7p";

    let (node, _services) = setup::setup()?;

    let tx_args = vec![
        "add",
        "--alias",
        "hw_pk",
        "--value",
        HARDWARE_WALLET_PK,
        "--unsafe-dont-encrypt",
    ];
    let captured = CapturedOutput::of(|| run(&node, Bin::Wallet, tx_args));
    assert_matches!(captured.result, Ok(_));

    let tx_args = vec![
        "transparent-transfer",
        "--source",
        BERTHA,
        "--target",
        HARDWARE_WALLET_IMPLICIT,
        "--token",
        NAM,
        "--amount",
        "1000.1",
        "--signing-keys",
        BERTHA_KEY,
        "--dry-run-wrapper",
        "--node",
        &validator_one_rpc,
    ];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(!captured.contains(TX_REJECTED));
    let matches = captured
        .matches("batch consumed [0-9]+")
        .expect("Test failed");
    let dry_run_gas =
        u64::from_str(matches.split(' ').next_back().expect("Test failed"))
            .expect("Test failed");
    let tx_args = vec![
        "transparent-transfer",
        "--source",
        BERTHA,
        "--target",
        HARDWARE_WALLET_IMPLICIT,
        "--token",
        NAM,
        "--amount",
        "1000.1",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_one_rpc,
    ];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    let matches = captured
        .matches("batch consumed [0-9]+")
        .expect("Test failed");
    let actual_gas =
        u64::from_str(matches.split(' ').next_back().expect("Test failed"))
            .expect("Test failed");

    // check that the gas difference is at most 10% different from the actual
    assert!(10 * dry_run_gas.abs_diff(actual_gas) <= actual_gas);

    let tx_args = apply_use_device(vec![
        "transparent-transfer",
        "--source",
        HARDWARE_WALLET_IMPLICIT,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "10.1",
        "--dry-run-wrapper",
        "--signing-keys",
        HARDWARE_WALLET_PK,
        "--gas-payer",
        HARDWARE_WALLET_IMPLICIT,
        "--node",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(!captured.contains(TX_REJECTED));
    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Submit an invalid transaction (disallowed by state machine)
/// 3. Check that the state was changed
#[test]
fn invalid_transactions() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";

    let (node, _services) = setup::setup()?;

    // 2. Submit an invalid transaction (trying to transfer tokens should fail
    // in the user's VP due to the insufficient balance)
    let daewon_lower = DAEWON.to_lowercase();
    let tx_args = apply_use_device(vec![
        "transparent-transfer",
        "--source",
        DAEWON,
        "--signing-keys",
        &daewon_lower,
        "--target",
        ALBERT,
        "--token",
        BERTHA,
        "--amount",
        "1000000.1",
        // Force to ignore client check that fails on the balance check of the
        // source address
        "--force",
        "--node",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert!(captured.contains(TX_INSUFFICIENT_BALANCE));

    node.finalize_and_commit(None);
    // There should be state now
    {
        let locked = node.shell.lock().unwrap();
        assert_ne!(
            locked.last_state("").last_block_app_hash,
            Default::default()
        );
    }

    Ok(())
}

/// Test for claiming PoS inflationary rewards
///
/// 1. Run the ledger node
/// 2. Wait some epochs while inflationary rewards accumulate in the PoS system
/// 3. Submit a claim-rewards tx
/// 4. Query the validator's balance before and after the claim tx to ensure
/// that reward tokens were actually transferred
#[test]
fn pos_rewards() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";

    let (mut node, _services) = setup::setup()?;
    // Query the current rewards for the validator self-bond
    let tx_args = vec![
        "rewards",
        "--validator",
        "validator-0-validator",
        "--node",
        &validator_one_rpc,
    ];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    let res = captured
        .matches(r"Current rewards available for claim: [0-9\.]+ NAM")
        .expect("Test failed");

    let words = res.split(' ').collect::<Vec<_>>();
    let res = words[words.len() - 2];
    let mut last_amount = token::Amount::from_str(
        res.split(' ').next_back().unwrap(),
        NATIVE_MAX_DECIMAL_PLACES,
    )
    .unwrap();

    for _ in 0..4 {
        node.next_epoch();
        // Query the current rewards for the validator self-bond and see that it
        // grows
        let tx_args = vec![
            "rewards",
            "--validator",
            "validator-0-validator",
            "--node",
            &validator_one_rpc,
        ];
        let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
        assert_matches!(captured.result, Ok(_));
        let res = captured
            .matches(r"Current rewards available for claim: [0-9\.]+ NAM")
            .expect("Test failed");

        let words = res.split(' ').collect::<Vec<_>>();
        let res = words[words.len() - 2];
        let amount = token::Amount::from_str(
            res.split(' ').next_back().unwrap(),
            NATIVE_MAX_DECIMAL_PLACES,
        )
        .unwrap();

        assert!(amount > last_amount);
        last_amount = amount;
    }

    // Query the balance of the validator account
    let query_balance_args = vec![
        "balance",
        "--owner",
        "validator-0-validator",
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    let res = captured.matches(r"nam: [0-9\.]+").expect("Test failed");
    let amount_pre = token::Amount::from_str(
        res.split(' ').next_back().unwrap(),
        NATIVE_MAX_DECIMAL_PLACES,
    )
    .unwrap();

    // Claim rewards
    let tx_args = apply_use_device(vec![
        "claim-rewards",
        "--validator",
        "validator-0-validator",
        "--signing-keys",
        "validator-0-account-key",
        "--node",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    println!("{:?}", captured.result);
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Query the validator balance again and check that the balance has grown
    // after claiming
    let query_balance_args = vec![
        "balance",
        "--owner",
        "validator-0-validator",
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    let res = captured.matches(r"nam: [0-9\.]+").expect("Test failed");
    let amount_post = token::Amount::from_str(
        res.split(' ').next_back().unwrap(),
        NATIVE_MAX_DECIMAL_PLACES,
    )
    .unwrap();
    assert!(amount_post > amount_pre);

    let query_staking_rewards_rate =
        vec!["staking-rewards-rate", "--node", &validator_one_rpc];
    let captured = CapturedOutput::of(|| {
        run(&node, Bin::Client, query_staking_rewards_rate)
    });
    assert_matches!(captured.result, Ok(_));
    let _res = captured
        .matches(r"Current annual staking rewards rate: 65.705255877354")
        .expect("Test failed");
    let _res = captured
        .matches(r"PoS inflation rate: 0.066593164444")
        .expect("Test failed");

    Ok(())
}

/// Test for PoS bonds and unbonds queries.
///
/// 1. Run the ledger node
/// 2. Submit a delegation to the genesis validator
/// 3. Wait for epoch 4
/// 4. Submit another delegation to the genesis validator
/// 5. Submit an unbond of the delegation
/// 6. Wait for epoch 7
/// 7. Check the output of the bonds query
#[test]
fn test_bond_queries() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // 1. start the ledger node
    let (mut node, _services) = setup::setup()?;

    let validator_alias = "validator-0-validator";
    // 2. Submit a delegation to the genesis validator
    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        validator_alias,
        "--amount",
        "100",
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 3. Submit a delegation to the genesis validator
    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        "validator-0-validator",
        "--source",
        BERTHA,
        "--amount",
        "200",
        "--signing-keys",
        BERTHA_KEY,
        "--ledger-address",
        &validator_one_rpc,
    ]);

    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 3. Wait for epoch 4
    for _ in 0..4 {
        node.next_epoch();
    }

    // 4. Submit another delegation to the genesis validator
    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        validator_alias,
        "--source",
        BERTHA,
        "--amount",
        "300",
        "--signing-keys",
        BERTHA_KEY,
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 5. Submit an unbond of the delegation
    let tx_args = apply_use_device(vec![
        "unbond",
        "--validator",
        validator_alias,
        "--source",
        BERTHA,
        "--amount",
        "412",
        "--signing-keys",
        BERTHA_KEY,
        "--ledger-address",
        &validator_one_rpc,
    ]);

    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    let res = captured
        .matches(r"withdrawable starting from epoch [0-9]+")
        .expect("Test failed");
    let withdraw_epoch =
        Epoch::from_str(res.split(' ').next_back().unwrap()).unwrap();

    // 6. Wait for withdraw_epoch
    loop {
        if node.current_epoch() >= withdraw_epoch {
            break;
        } else {
            node.next_epoch();
        }
    }

    // 7. Check the output of the bonds query
    let tx_args = vec!["bonds", "--ledger-address", &validator_one_rpc];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(
        "All bonds total active: 120188.000000
All bonds total: 120188.000000
All bonds total slashed: 0.000000
All unbonds total active: 412.000000
All unbonds total: 412.000000
All unbonds total withdrawable: 412.000000
All unbonds total slashed: 0.000000",
    ));

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Submit a valid proposal
/// 3. Query the proposal
/// 4. Query token balance (submitted funds)
/// 5. Query governance address balance
/// 6. Submit an invalid proposal
/// 7. Check invalid proposal was not accepted
/// 8. Query token balance (funds shall not be submitted)
/// 9. Send a yay vote from a validator
/// 10. Send a yay vote from a normal user
/// 11. Query the proposal and check the result
/// 12. Wait proposal grace and check proposal author funds
/// 13. Check governance address funds are 0
/// 14. Query the new parameters
/// 15. Try to initialize a new account which should fail
/// 16. Submit a tx that triggers an already existing account which should
///     succeed
#[test]
fn proposal_submission() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // 1. start the ledger node
    let (mut node, _services) = setup::setup()?;

    // 1.1 Delegate some token
    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        "validator-0-validator",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--node",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 2. Submit valid proposal
    let albert = defaults::albert_address();
    let valid_proposal_json_path = prepare_proposal_data(
        node.test_dir.path(),
        albert.clone(),
        TestWasms::TxProposalCode.read_bytes(),
        12,
    );

    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--gas-limit",
        "2200000",
        "--node",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 3. Query the proposal
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "0",
        "--node",
        &validator_one_rpc,
    ];

    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, proposal_query_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("Proposal Id: 0"));

    // 4. Query token balance proposal author (submitted funds)
    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1979500"));

    // 5. Query token balance governance
    let query_balance_args = vec![
        "balance",
        "--owner",
        GOVERNANCE_ADDRESS,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 500"));

    // 9.1. Send a yay vote from a validator
    while node.current_epoch().0 <= 13 {
        node.next_epoch();
    }

    let submit_proposal_vote = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        "validator-0-validator",
        "--node",
        &validator_one_rpc,
    ]);

    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_vote));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 9.2. Send a valid yay vote from a delegator with bonds
    let submit_proposal_vote_delegator = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "nay",
        "--address",
        BERTHA,
        "--node",
        &validator_one_rpc,
    ]);

    let captured = CapturedOutput::of(|| {
        run(&node, Bin::Client, submit_proposal_vote_delegator)
    });
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 10. Send a yay vote from a non-validator/non-delegator user
    let submit_proposal_vote = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        CHRISTEL,
        "--node",
        &validator_one_rpc,
    ]);

    // Expect a client failure here
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_vote));
    assert!(captured.result.is_err());
    assert!(captured.err_contains(r"The account .* has no active delegations"));

    // 11. Query the proposal and check the result
    while node.current_epoch().0 <= 25 {
        node.next_epoch();
    }

    let query_proposal = vec![
        "query-proposal-result",
        "--proposal-id",
        "0",
        "--node",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_proposal));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("Proposal Id: 0"));
    let expected = regex::escape(
        "Passed with 120000.000000 yay votes, 900.000000 nay votes and \
         0.000000 abstain votes, total voting power: 120900.000000, threshold \
         (fraction) of total voting power needed to tally: 48360.000000 (0.4)",
    );
    assert!(captured.contains(&expected));

    // 12. Wait proposal grace and check proposal author funds
    while node.current_epoch().0 < 31 {
        node.next_epoch();
    }

    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1980000"));

    // 13. Check if governance funds are 0
    let query_balance_args = vec![
        "balance",
        "--owner",
        GOVERNANCE_ADDRESS,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 0"));

    // 14. Query parameters
    let query_protocol_parameters =
        vec!["query-protocol-parameters", "--node", &validator_one_rpc];
    let captured = CapturedOutput::of(|| {
        run(&node, Bin::Client, query_protocol_parameters)
    });
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(".*Min. proposal grace epochs: 9.*"));

    // 15. Try to initialize a new account with the no more allowlisted vp
    let init_account = apply_use_device(vec![
        "init-account",
        "--public-keys",
        // Value obtained from
        // `namada_sdk::key::ed25519::tests::gen_keypair`
        "tpknam1qpqfzxu3gt05jx2mvg82f4anf90psqerkwqhjey4zlqv0qfgwuvkzt5jhkp",
        "--threshold",
        "1",
        "--code-path",
        VP_USER_WASM,
        "--alias",
        "Test-Account",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, init_account));
    assert_matches!(captured.result, Ok(_));
    assert!(
        captured.contains(".*VP code is not allowed in allowlist parameter.*")
    );

    // 16. Submit a tx touching a previous account with the no more allowlisted
    //     vp and verify that the transaction succeeds, i.e. the non allowlisted
    //     vp can still run
    let transfer = apply_use_device(vec![
        "transparent-transfer",
        "--source",
        BERTHA,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "10",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, transfer));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    Ok(())
}

#[test]
fn inflation() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // 1. start the ledger node
    let (mut node, _services) = setup::initialize_genesis(|mut genesis| {
        genesis.parameters.pos_params.max_inflation_rate =
            Dec::from_str("0.1").unwrap();
        genesis.parameters.pgf_params.stewards_inflation_rate =
            Dec::from_str("0.1").unwrap();
        genesis.parameters.pgf_params.pgf_inflation_rate =
            Dec::from_str("0.1").unwrap();
        genesis.parameters.pgf_params.stewards =
            BTreeSet::from_iter([defaults::albert_address()]);
        genesis
    })?;

    let pos_inflation = [
        118400000.813463,
        118400001.689407,
        118400002.627832,
        118400003.628738,
        118400004.692125,
    ];
    let steward_inflation = [
        1980000.375443,
        1980000.750886,
        1980001.126329,
        1980001.501772,
        1980001.877215,
    ];
    let pgf_inflation = [0.41299, 0.819698, 1.242026, 1.679974, 2.133543];

    for epoch in 0..5 {
        node.next_epoch();

        let query_total_supply_args = vec![
            "total-supply",
            "--token",
            NAM,
            "--ledger-address",
            &validator_one_rpc,
        ];
        let captured = CapturedOutput::of(|| {
            run(&node, Bin::Client, query_total_supply_args)
        });
        assert_matches!(captured.result, Ok(_));
        assert!(captured.contains(&format!(
            "token tnam1q9kn74xfzytqkqyycfrhycr8ajam8ny935cge0z5: {}",
            pos_inflation[epoch]
        )));

        let query_balance_args = vec![
            "balance",
            "--owner",
            PGF_ADDRESS,
            "--token",
            NAM,
            "--ledger-address",
            &validator_one_rpc,
        ];
        let captured =
            CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
        assert_matches!(captured.result, Ok(_));
        assert!(captured.contains(&format!("nam: {}", pgf_inflation[epoch])));

        let query_balance_args = vec![
            "balance",
            "--owner",
            ALBERT,
            "--token",
            NAM,
            "--ledger-address",
            &validator_one_rpc,
        ];
        let captured =
            CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
        assert_matches!(captured.result, Ok(_));
        assert!(
            captured.contains(&format!("nam: {}", steward_inflation[epoch]))
        );

        let query_balance_args = vec![
            "balance",
            "--owner",
            BERTHA,
            "--token",
            NAM,
            "--ledger-address",
            &validator_one_rpc,
        ];
        let captured =
            CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
        assert_matches!(captured.result, Ok(_));
        assert!(captured.contains(&format!("nam: {}", 2000000)));
    }

    Ok(())
}

/// Test adding and removal of continuous PGF proposal payments
///
/// 1. Submit a first funding proposal where
///   - Add ALB - 10k unam until epoch 52
///   - Add CHR - 35k unam indefinitely
/// 2. Query the proposal
/// 3. Vote for the accepted proposals and query balances
/// 4. Check the result passed
/// 5. Wait until activation epoch and check balances
/// 6. Submit a new funding proposal where
///   - Remove CHR - prop 0
///   - Add CHR - 75k unam until epoch 71
///   - Add EST - 66.6k unam indefinitely
///   - Add ALB - 166 unam until epoch 55
/// 7. Vote and confirm it passes then wait until activation epoch
/// 8. Query balances
/// 9. Query PGF fundings
/// 10. Advance to epoch 52 and check that the ALB prop 0 cPGF has expired
/// 10. Submit a new funding proposal where
///   - Remove EST - prop 1
/// 11. Vote on proposal and pass it
/// 12. Advance to epoch 71 and confirm that no cPGF exists anymore
#[test]
fn continuous_pgf_proposals() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // 1. start the ledger node
    let (mut node, _services) = setup::setup()?;

    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        "validator-0-validator",
        "--source",
        BERTHA,
        "--amount",
        "100000",
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    let albert = defaults::albert_address();
    let ester = defaults::ester_address();
    let christel = defaults::christel_address();

    println!(
        "\n\nALBERT: {}\nESTER: {}\nCHRISTEL: {}\n\n",
        &albert, &ester, &christel
    );

    // 1. Submit first PGF funding proposal
    let pgf_funding = PgfFunding {
        continuous: vec![
            PgfContinuous {
                target: ContPGFTarget {
                    target: PGFTarget::Internal(PGFInternalTarget {
                        amount: token::Amount::from_u64(10_000),
                        target: albert.clone(),
                    }),
                    end_epoch: Some(Epoch(52)),
                    proposal_id: 999999, // doesn't matter
                },
                action: PgfAction::Add,
            },
            PgfContinuous {
                target: ContPGFTarget {
                    target: PGFTarget::Internal(PGFInternalTarget {
                        amount: token::Amount::from_u64(35_000),
                        target: christel.clone(),
                    }),
                    end_epoch: None,
                    proposal_id: 9999999, // doesn't matter
                },
                action: PgfAction::Add,
            },
        ],
        retro: vec![PGFTarget::Internal(PGFInternalTarget {
            amount: token::Amount::from_u64(5),
            target: ester.clone(),
        })],
    };

    let valid_proposal_json_path = prepare_proposal_data(
        node.test_dir.path(),
        albert.clone(),
        pgf_funding,
        12,
    );
    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--pgf-funding",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 2. Query the proposal
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "0",
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, proposal_query_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("Proposal Id: 0"));

    // Query token balance proposal author (submitted funds)
    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1979500"));

    // Query token balance governance
    let query_balance_args = vec![
        "balance",
        "--owner",
        GOVERNANCE_ADDRESS,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 500"));

    // 3. Send a yay vote from a validator
    while node.current_epoch().0 <= 13 {
        node.next_epoch();
    }

    let submit_proposal_vote = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        "validator-0-validator",
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_vote));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Send different yay vote from delegator to check majority on 1/3
    let submit_proposal_vote_delegator = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        BERTHA,
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| {
        run(&node, Bin::Client, submit_proposal_vote_delegator)
    });
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    while node.current_epoch().0 <= 25 {
        node.next_epoch();
    }

    let query_proposal = vec![
        "query-proposal-result",
        "--proposal-id",
        "0",
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_proposal));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("Passed"));

    // 5. Wait for proposal activation epoch and check proposal author funds
    while node.current_epoch().0 < 30 {
        node.next_epoch();
    }
    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1980000.01"));

    let query_balance_args = vec![
        "balance",
        "--owner",
        CHRISTEL,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 2000000.035"));

    let query_pgf = vec!["query-pgf", "--node", &validator_one_rpc];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, query_pgf));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("Continuous PGF distributions"));
    assert!(captured.contains(&format!("- {}", &christel)));
    assert!(
        captured.contains("- Prop 0: 0.035000 native tokens, end epoch = None")
    );
    assert!(captured.contains(&format!("- {}", &albert)));
    assert!(
        captured.contains("- Prop 0: 0.010000 native tokens, end epoch = 52")
    );

    // 6. Submit a new cPGF proposal
    let pgf_funding = PgfFunding {
        continuous: vec![
            PgfContinuous {
                target: ContPGFTarget {
                    target: PGFTarget::Internal(PGFInternalTarget {
                        amount: token::Amount::zero(), // doesn't matter
                        target: christel.clone(),
                    }),
                    end_epoch: Some(Epoch(999999)), // doesn't matter
                    proposal_id: 0,
                },
                action: PgfAction::Remove,
            },
            PgfContinuous {
                target: ContPGFTarget {
                    target: PGFTarget::Internal(PGFInternalTarget {
                        amount: token::Amount::from_u64(75000),
                        target: christel.clone(),
                    }),
                    end_epoch: Some(Epoch(71)),
                    proposal_id: 9999999, // doesn't matter
                },
                action: PgfAction::Add,
            },
            PgfContinuous {
                target: ContPGFTarget {
                    target: PGFTarget::Internal(PGFInternalTarget {
                        amount: token::Amount::from_u64(66_600),
                        target: ester.clone(),
                    }),
                    end_epoch: None,
                    proposal_id: 9999999, // doesn't matter
                },
                action: PgfAction::Add,
            },
            PgfContinuous {
                target: ContPGFTarget {
                    target: PGFTarget::Internal(PGFInternalTarget {
                        amount: token::Amount::from_u64(166),
                        target: albert.clone(),
                    }),
                    end_epoch: Some(Epoch(55)),
                    proposal_id: 9999999, // doesn't matter
                },
                action: PgfAction::Add,
            },
        ],
        retro: vec![],
    };

    let valid_proposal_json_path = prepare_proposal_data(
        node.test_dir.path(),
        albert.clone(),
        pgf_funding,
        31,
    );
    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--pgf-funding",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    node.next_epoch();
    let submit_proposal_vote = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "1",
        "--vote",
        "yay",
        "--address",
        "validator-0-validator",
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_vote));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Send different yay vote from delegator to check majority on 1/3
    let submit_proposal_vote_delegator = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "1",
        "--vote",
        "yay",
        "--address",
        BERTHA,
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| {
        run(&node, Bin::Client, submit_proposal_vote_delegator)
    });
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1979500.02"));

    let query_balance_args = vec![
        "balance",
        "--owner",
        CHRISTEL,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 2000000.07"));

    // Wait until activation epoch
    while node.current_epoch().0 < 49 {
        node.next_epoch();
    }

    // 11. Query pgf fundings
    let query_pgf = vec!["query-pgf", "--node", &validator_one_rpc];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, query_pgf));
    assert_matches!(captured.result, Ok(_));

    assert!(captured.contains("Continuous PGF distributions"));
    assert!(captured.contains(&format!("- {}", &ester)));
    assert!(
        captured.contains("- Prop 1: 0.066600 native tokens, end epoch = None")
    );
    assert!(captured.contains(&format!("- {}", &christel)));
    assert!(
        captured.contains("- Prop 1: 0.075000 native tokens, end epoch = 71")
    );
    assert!(captured.contains(&format!("- {}", &albert)));
    assert!(
        captured.contains("- Prop 0: 0.010000 native tokens, end epoch = 52")
    );
    assert!(
        captured.contains("- Prop 1: 0.000166 native tokens, end epoch = 55")
    );

    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1980000.200166"));

    let query_balance_args = vec![
        "balance",
        "--owner",
        CHRISTEL,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 2000000.74"));

    let query_balance_args = vec![
        "balance",
        "--owner",
        ESTER,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1000000.066605"));

    while node.current_epoch().0 < 52 {
        node.next_epoch();
    }
    let query_pgf = vec!["query-pgf", "--node", &validator_one_rpc];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, query_pgf));
    assert_matches!(captured.result, Ok(_));

    // TODO: How can I check the absence of a string??

    assert!(captured.contains("Continuous PGF distributions"));
    assert!(captured.contains(&format!("- {}", &ester)));
    assert!(
        captured.contains("- Prop 1: 0.066600 native tokens, end epoch = None")
    );
    assert!(captured.contains(&format!("- {}", &christel)));
    assert!(
        captured.contains("- Prop 1: 0.075000 native tokens, end epoch = 71")
    );
    assert!(captured.contains(&format!("- {}", &albert)));
    assert!(
        captured.contains("- Prop 1: 0.000166 native tokens, end epoch = 55")
    );

    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1980000.220664"));

    let query_balance_args = vec![
        "balance",
        "--owner",
        CHRISTEL,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 2000000.965"));

    let query_balance_args = vec![
        "balance",
        "--owner",
        ESTER,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1000000.266405"));

    let pgf_funding = PgfFunding {
        continuous: vec![PgfContinuous {
            target: ContPGFTarget {
                target: PGFTarget::Internal(PGFInternalTarget {
                    amount: token::Amount::zero(), // doesn't matter
                    target: ester.clone(),
                }),
                end_epoch: Some(Epoch(0)), // doesn't matter
                proposal_id: 1,
            },
            action: PgfAction::Remove,
        }],
        retro: vec![],
    };

    let valid_proposal_json_path = prepare_proposal_data(
        node.test_dir.path(),
        albert.clone(),
        pgf_funding,
        53,
    );
    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--pgf-funding",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    node.next_epoch();
    let submit_proposal_vote = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "2",
        "--vote",
        "yay",
        "--address",
        "validator-0-validator",
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_vote));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Send different yay vote from delegator to check majority on 1/3
    let submit_proposal_vote_delegator = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "2",
        "--vote",
        "yay",
        "--address",
        BERTHA,
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| {
        run(&node, Bin::Client, submit_proposal_vote_delegator)
    });
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 10. Wait
    while node.current_epoch().0 < 71 {
        node.next_epoch();
    }
    let query_pgf = vec!["query-pgf", "--node", &validator_one_rpc];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, query_pgf));
    assert_matches!(captured.result, Ok(_));

    assert!(
        captured.contains("No continous PGF distributions exist currently")
    );

    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1980000.220996"));

    let query_balance_args = vec![
        "balance",
        "--owner",
        CHRISTEL,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 2000002.315"));

    let query_balance_args = vec![
        "balance",
        "--owner",
        ESTER,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1000001.465205"));

    Ok(())
}

/// Test submission and vote of a PGF proposal
///
/// 1. Submit proposal
/// 2. Query the proposal
/// 3. Vote for the accepted proposals and query balances
/// 4. Query the proposal and check the result is the one voted by the validator
///    (majority)
/// 5. Wait proposals grace and check proposal author funds
/// 6. Check if governance funds are 0
/// 7. Query pgf stewards
/// 8. Submit proposal funding
/// 9. Query the funding proposal
/// 10. Wait proposals grace and check proposal author funds
/// 11. Query pgf fundings
#[test]
fn pgf_governance_proposal() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // 1. start the ledger node
    let (mut node, _services) = setup::setup()?;

    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        "validator-0-validator",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 1. Submit proposal
    let albert = defaults::albert_address();
    let pgf_stewards = StewardsUpdate {
        add: Some(albert.clone()),
        remove: vec![],
    };

    let valid_proposal_json_path =
        prepare_proposal_data(node.test_dir.path(), albert, pgf_stewards, 12);
    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--pgf-stewards",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 2. Query the proposal
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "0",
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, proposal_query_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("Proposal Id: 0"));

    // Query token balance proposal author (submitted funds)
    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1979500"));

    // Query token balance governance
    let query_balance_args = vec![
        "balance",
        "--owner",
        GOVERNANCE_ADDRESS,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 500"));

    // 3. Send a yay vote from a validator
    while node.current_epoch().0 <= 13 {
        node.next_epoch();
    }

    let submit_proposal_vote = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        "validator-0-validator",
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_vote));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Send different yay vote from delegator to check majority on 1/3
    let submit_proposal_vote_delegator = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        BERTHA,
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| {
        run(&node, Bin::Client, submit_proposal_vote_delegator)
    });
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 4. Query the proposal and check the result is the one voted by the
    // validator (majority)
    while node.current_epoch().0 <= 25 {
        node.next_epoch();
    }

    let query_proposal = vec![
        "query-proposal-result",
        "--proposal-id",
        "0",
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_proposal));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("Passed"));

    // 5. Wait proposals grace and check proposal author funds
    while node.current_epoch().0 < 31 {
        node.next_epoch();
    }
    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 1980000"));

    // 6. Check if governance funds are 0
    let query_balance_args = vec![
        "balance",
        "--owner",
        GOVERNANCE_ADDRESS,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 0"));

    // 7. Query pgf stewards
    let query_pgf = vec!["query-pgf", "--node", &validator_one_rpc];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, query_pgf));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("PGF stewards:"));
    assert!(captured.contains(&format!("- {}", defaults::albert_address())));
    assert!(captured.contains("Reward distribution:"));
    assert!(
        captured.contains(&format!("- 1 to {}", defaults::albert_address()))
    );
    assert!(
        captured.contains("No continous PGF distributions exist currently.")
    );

    // 7.1 Query total NAM supply and PGF balance
    let query_balance_args = vec![
        "balance",
        "--owner",
        PGF_ADDRESS,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_balance_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 14.267253"));

    let query_total_supply_args = vec![
        "total-supply",
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_total_supply_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(
        "token tnam1q9kn74xfzytqkqyycfrhycr8ajam8ny935cge0z5: 118400024.740301"
    ));

    let query_native_supply_args =
        vec!["native-supply", "--ledger-address", &validator_one_rpc];
    let captured = CapturedOutput::of(|| {
        run(&node, Bin::Client, query_native_supply_args)
    });
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("nam: 118400010.473048"));

    // 8. Submit proposal funding
    let albert = defaults::albert_address();
    let bertha = defaults::bertha_address();
    let christel = defaults::christel_address();
    let cont_end_epoch = Epoch::from(70);

    let pgf_funding = PgfFunding {
        continuous: vec![
            PgfContinuous {
                target: ContPGFTarget {
                    target: PGFTarget::Internal(PGFInternalTarget {
                        amount: token::Amount::from_u64(10),
                        target: bertha.clone(),
                    }),
                    end_epoch: Some(cont_end_epoch),
                    proposal_id: 0,
                },
                action: PgfAction::Add,
            },
            PgfContinuous {
                target: ContPGFTarget {
                    target: PGFTarget::Internal(PGFInternalTarget {
                        amount: token::Amount::from_u64(35),
                        target: christel.clone(),
                    }),
                    end_epoch: None,
                    proposal_id: 0,
                },
                action: PgfAction::Add,
            },
        ],
        retro: vec![PGFTarget::Internal(PGFInternalTarget {
            amount: token::Amount::from_u64(5),
            target: christel.clone(),
        })],
    };
    let valid_proposal_json_path = prepare_proposal_data(
        node.test_dir.path(),
        albert.clone(),
        pgf_funding,
        36,
    );

    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--pgf-funding",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--ledger-address",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, submit_proposal_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 9. Query the funding proposal
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "1",
        "--ledger-address",
        &validator_one_rpc,
    ];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, proposal_query_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("Proposal Id: 1"));

    // 10. Wait proposals grace and check proposal author funds
    while node.current_epoch().0 < 55 {
        node.next_epoch();
    }

    // 11. Query pgf fundings
    let query_pgf = vec!["query-pgf", "--node", &validator_one_rpc];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, query_pgf));
    assert_matches!(captured.result, Ok(_));

    assert!(captured.contains("Continuous PGF distributions"));
    assert!(captured.contains(&format!("- {}", &bertha)));
    assert!(
        captured.contains("- Prop 1: 0.000010 native tokens, end epoch = 70")
    );
    assert!(captured.contains(&format!("- {}", &christel)));
    assert!(
        captured.contains("- Prop 1: 0.000035 native tokens, end epoch = None")
    );

    Ok(())
}

/// Test if a steward can correctly change his distribution reward
#[test]
fn pgf_steward_change_commission() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // 1. start the ledger node
    let (node, _services) = setup::initialize_genesis(|mut genesis| {
        genesis.parameters.pgf_params.stewards_inflation_rate =
            Dec::from_str("0.1").unwrap();
        genesis.parameters.pgf_params.stewards =
            BTreeSet::from_iter([defaults::albert_address()]);
        genesis
    })?;

    // Query pgf stewards
    let query_pgf = vec!["query-pgf", "--node", &validator_one_rpc];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, query_pgf));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("PGF stewards:"));
    assert!(captured.contains(&format!("- {}", defaults::albert_address())));
    assert!(captured.contains("Reward distribution:"));
    assert!(
        captured.contains(&format!("- 1 to {}", defaults::albert_address()))
    );
    assert!(
        captured.contains("No continous PGF distributions exist currently.")
    );

    let commission = Commission {
        reward_distribution: HashMap::from_iter([
            (defaults::albert_address(), Dec::from_str("0.25").unwrap()),
            (defaults::bertha_address(), Dec::from_str("0.70").unwrap()),
            (defaults::christel_address(), Dec::from_str("0.05").unwrap()),
        ]),
    };
    let commission_path = prepare_steward_commission_update_data(
        node.test_dir.path(),
        commission,
    );
    // Update steward commissions
    let tx_args = apply_use_device(vec![
        "update-steward-rewards",
        "--steward",
        ALBERT,
        "--data-path",
        commission_path.to_str().unwrap(),
        "--node",
        &validator_one_rpc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 14. Query pgf stewards
    let query_pgf = vec!["query-pgf", "--node", &validator_one_rpc];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, query_pgf));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("PGF stewards:"));
    assert!(captured.contains(&format!("- {}", defaults::albert_address())));
    assert!(captured.contains("Reward distribution:"));
    assert!(
        captured.contains(&format!("- 0.25 to {}", defaults::albert_address()))
    );
    assert!(
        captured.contains(&format!("- 0.7 to {}", defaults::bertha_address()))
    );
    assert!(
        captured
            .contains(&format!("- 0.05 to {}", defaults::christel_address()))
    );
    assert!(
        captured.contains("No continous PGF distributions exist currently.")
    );

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. For some transactions that need signature authorization: 2a. Generate a
///    new key for an implicit account. 2b. Send some funds to the implicit
///    account. 2c. Submit the tx with the implicit account as the source, that
///    requires that the account has revealed its PK. This should be done by the
///    client automatically. 2d. Submit same tx again, this time the client
///    shouldn't reveal again.
#[test]
fn implicit_account_reveal_pk() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // 1. start the ledger node
    let (node, _services) = setup::setup()?;
    // 2. Some transactions that need signature authorization:
    #[allow(clippy::type_complexity)]
    let txs_args: Vec<Box<dyn Fn(&str) -> Vec<String>>> = vec![
        // Submit proposal
        Box::new(|source| {
            // Gen data for proposal tx
            let author = find_address(&node, source).unwrap();
            let valid_proposal_json_path = prepare_proposal_data(
                node.test_dir.path(),
                author,
                TestWasms::TxProposalCode.read_bytes(),
                12,
            );
            vec![
                "init-proposal",
                "--data-path",
                valid_proposal_json_path.to_str().unwrap(),
                "--signing-keys",
                source,
                "--gas-limit",
                "2200000",
                "--node",
                &validator_one_rpc,
            ]
            .into_iter()
            .map(|x| x.to_owned())
            .collect()
        }),
        // A token transfer tx
        Box::new(|source| {
            [
                "transparent-transfer",
                "--source",
                source,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "10.1",
                "--signing-keys",
                source,
                "--node",
                validator_one_rpc,
            ]
            .into_iter()
            .map(|x| x.to_owned())
            .collect()
        }),
        // A bond
        Box::new(|source| {
            vec![
                "bond",
                "--validator",
                "validator-0-validator",
                "--source",
                source,
                "--amount",
                "10.1",
                "--signing-keys",
                source,
                "--node",
                &validator_one_rpc,
            ]
            .into_iter()
            .map(|x| x.to_owned())
            .collect()
        }),
    ];

    for (ix, tx_args) in txs_args.into_iter().enumerate() {
        let key_alias = format!("key-{ix}");
        // 2a. Generate a new key for an implicit account.
        run(
            &node,
            Bin::Wallet,
            vec![
                "gen",
                "--alias",
                &key_alias,
                "--unsafe-dont-encrypt",
                "--raw",
            ],
        )?;
        // Apply the key_alias once the key is generated to obtain tx args
        let tx_args = tx_args(&key_alias);
        // 2b. Send some funds to the implicit account.
        let credit_args = apply_use_device(vec![
            "transparent-transfer",
            "--source",
            BERTHA,
            "--target",
            &key_alias,
            "--token",
            NAM,
            "--amount",
            "2000",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ]);
        let captured =
            CapturedOutput::of(|| run(&node, Bin::Client, credit_args));
        assert!(captured.result.is_ok());
        assert!(captured.contains(TX_APPLIED_SUCCESS));

        // 2c. Submit the tx with the implicit account as the source.
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                tx_args.iter().map(|arg| arg.as_ref()).collect(),
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains("Submitting a tx to reveal the public key"));
        assert!(captured.contains(TX_APPLIED_SUCCESS));

        // 2d. Submit same tx again, this time the client shouldn't reveal
        // again.
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                tx_args.iter().map(|arg| arg.as_ref()).collect(),
            )
        });
        assert!(captured.result.is_ok());
        assert!(!captured.contains("Submitting a tx to reveal the public key"));
        assert!(captured.result.is_ok());
        assert!(captured.contains(TX_APPLIED_SUCCESS));
    }

    Ok(())
}

/// Change validator metadata
#[test]
fn change_validator_metadata() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // 1. start the ledger node
    let (node, _services) = setup::setup()?;

    // 2. Query the validator metadata loaded from genesis
    let metadata_query_args = vec![
        "validator-metadata",
        "--validator",
        "validator-0-validator",
        "--node",
        &validator_one_rpc,
    ];
    let captured = CapturedOutput::of(|| {
        run(&node, Bin::Client, metadata_query_args.clone())
    });
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("No validator name"));
    assert!(captured.contains("Email:"));
    assert!(captured.contains("No description"));
    assert!(captured.contains("No website"));
    assert!(captured.contains("No discord handle"));
    assert!(captured.contains("commission rate:"));
    assert!(captured.contains("max change per epoch:"));

    // 3. Add some metadata to the validator
    let metadata_change_args = apply_use_device(vec![
        "change-metadata",
        "--validator",
        "validator-0-validator",
        "--name",
        "theokayestvalidator",
        "--email",
        "theokayestvalidator@namada.net",
        "--description",
        "We are just an okay validator node trying to get by",
        "--website",
        "theokayestvalidator.com",
        "--node",
        &validator_one_rpc,
    ]);

    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, metadata_change_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 4. Query the metadata after the change
    let captured = CapturedOutput::of(|| {
        run(&node, Bin::Client, metadata_query_args.clone())
    });
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("Validator name: theokayestvalidator"));
    assert!(captured.contains("Email: theokayestvalidator@namada.net"));
    assert!(captured.contains(
        "Description: We are just an okay validator node trying to get by"
    ));
    assert!(captured.contains("Website: theokayestvalidator.com"));
    assert!(captured.contains("No discord handle"));
    assert!(captured.contains("commission rate:"));
    assert!(captured.contains("max change per epoch:"));

    // 5. Remove the validator website
    let metadata_change_args = apply_use_device(vec![
        "change-metadata",
        "--validator",
        "validator-0-validator",
        "--website",
        "",
        "--node",
        &validator_one_rpc,
    ]);
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, metadata_change_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 6. Query the metadata to see that the validator website is removed
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, metadata_query_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains("Validator name: theokayestvalidator"));
    assert!(captured.contains("Email: theokayestvalidator@namada.net"));
    assert!(captured.contains(
        "Description: We are just an okay validator node trying to get by"
    ));
    assert!(captured.contains("No website"));
    assert!(captured.contains("No discord handle"));
    assert!(captured.contains("commission rate:"));
    assert!(captured.contains("max change per epoch:"));

    Ok(())
}

#[test]
fn offline_sign() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";

    // 1. start the ledger node
    let (node, _services) = setup::setup()?;

    // Initialize accounts we can access the secret keys of
    let (bradley_alias, _bradley_key) =
        make_temp_account(&node, validator_one_rpc, "Bradley", NAM, 500_000)?;
    let (cooper_alias, _cooper_key) =
        make_temp_account(&node, validator_one_rpc, "Cooper", NAM, 500_000)?;

    let output_folder = tempfile::tempdir().unwrap();

    // 2. Dump a wrapped transfer tx
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                bradley_alias,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "100",
                "--gas-limit",
                "200000",
                "--gas-price",
                "1",
                "--gas-payer",
                cooper_alias,
                "--node",
                &validator_one_rpc,
                "--dump-wrapper-tx",
                "--output-folder-path",
                &output_folder.path().to_str().unwrap(),
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let offline_tx = find_files_with_ext(output_folder.path(), "tx")
        .unwrap()
        .first()
        .expect("Offline tx should be found.")
        .to_path_buf()
        .display()
        .to_string();

    // 3. Sign the transaction offline
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "utils",
                "sign-offline",
                "--data-path",
                &offline_tx,
                "--secret-keys",
                &bradley_alias,
                "--secret-key",
                &cooper_alias,
                "--output-folder-path",
                &output_folder.path().to_str().unwrap(),
            ],
        )
    });
    assert!(captured.result.is_ok());

    let sig_files = find_files_with_ext(output_folder.path(), "sig").unwrap();
    assert_eq!(sig_files.len(), 2);

    let offline_sig = sig_files
        .iter()
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("offline_signature")
        })
        .expect("Offline signature should be found.")
        .to_path_buf()
        .display()
        .to_string();
    let offline_wrapper_sig = sig_files
        .iter()
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("offline_wrapper_signature")
        })
        .expect("Offline wrapper signature should be found.")
        .to_path_buf()
        .display()
        .to_string();

    // 4. Submit the signed transaction
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "tx",
                "--tx-path",
                &offline_tx,
                "--signatures",
                &offline_sig,
                "--gas-signature",
                &offline_wrapper_sig,
                "--node",
                &validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 5. Assert changed balances
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                bradley_alias,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 499900"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                cooper_alias,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 300000"));

    Ok(())
}

// Test that fee payment is enforced and aligned with process proposal. The test
// generates a tx that subtract funds from the fee payer of a following tx. Test
// that wrappers (and fee payments) are evaluated before the inner transactions.
#[test]
fn enforce_fee_payment() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // 1. start the ledger node
    let (node, _services) = setup::setup()?;

    // Initialize accounts we can access the secret keys of
    let (adam_alias, adam_key) =
        make_temp_account(&node, validator_one_rpc, "Adam", NAM, 2_000_000)?;

    let tempdir = tempfile::tempdir().unwrap();
    let mut txs_bytes = vec![];

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                adam_alias,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2000000"));

    run(
        &node,
        Bin::Client,
        apply_use_device(vec![
            "transparent-transfer",
            "--source",
            adam_alias,
            "--target",
            BERTHA,
            "--token",
            NAM,
            "--amount",
            // We want this transaction to consume all the remaining available
            // balance. If we executed the inner txs right after the
            // corresponding wrapper's fee payment this would succeed (but
            // this is not the case)
            "1900000",
            "--output-folder-path",
            tempdir.path().to_str().unwrap(),
            "--dump-tx",
            "--ledger-address",
            validator_one_rpc,
        ]),
    )?;
    assert!(captured.result.is_ok());
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    txs_bytes.push(std::fs::read(&file_path).unwrap());
    std::fs::remove_file(&file_path).unwrap();

    run(
        &node,
        Bin::Client,
        apply_use_device(vec![
            "transparent-transfer",
            "--source",
            adam_alias,
            "--target",
            CHRISTEL,
            "--token",
            NAM,
            "--amount",
            "50",
            "--gas-payer",
            adam_alias,
            "--output-folder-path",
            tempdir.path().to_str().unwrap(),
            "--dump-tx",
            "--ledger-address",
            validator_one_rpc,
        ]),
    )?;
    assert!(captured.result.is_ok());
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    txs_bytes.push(std::fs::read(&file_path).unwrap());
    std::fs::remove_file(&file_path).unwrap();

    let sk = adam_key;
    let pk = sk.to_public();

    let native_token = node
        .shell
        .lock()
        .unwrap()
        .state
        .in_mem()
        .native_token
        .clone();

    let mut txs = vec![];
    for bytes in txs_bytes {
        let mut tx = Tx::try_from_json_bytes(&bytes).unwrap();
        tx.add_wrapper(
            tx::data::wrapper::Fee {
                amount_per_gas_unit: DenominatedAmount::native(
                    token::Amount::native_whole(1),
                ),
                token: native_token.clone(),
            },
            pk.clone(),
            100_000.into(),
        );
        tx.sign_raw(vec![sk.clone()], AccountPublicKeysMap::default(), None);
        tx.sign_wrapper(sk.clone());

        txs.push(tx.to_bytes());
    }

    node.clear_results();
    node.submit_txs(txs);
    // If empty than failed in process proposal
    let codes = node.tx_result_codes.lock().unwrap();
    assert!(!codes.is_empty());

    for code in codes.iter() {
        assert!(matches!(code, NodeResults::Ok));
    }

    let results = node.tx_results.lock().unwrap();
    // We submitted two batches
    assert_eq!(results.len(), 2);
    let first_result = &results[0];
    let second_result = &results[1];

    // The batches should contain a single inner tx each
    assert_eq!(first_result.len(), 1);
    assert_eq!(second_result.len(), 1);

    // First transaction pay fees but then fails on the token transfer because
    // of a lack of funds
    assert!(first_result.are_any_err());
    // Second transaction is correctly applied
    assert!(second_result.are_results_successfull());

    // Assert balances
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                adam_alias,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    // This is the result of the two fee payments and the successful transfer to
    // Christel
    assert!(captured.contains("nam: 1799950"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                BERTHA,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    // Bertha must not receive anything because the transaction fails. This is
    // because we evaluate fee payments before the inner transactions, so by the
    // time we execute the transfer, Albert doesn't have enough funds anymore
    assert!(captured.contains("nam: 2000000"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                CHRISTEL,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2000050"));
    Ok(())
}

/// Test that we can successfully apply a snapshot
/// from one node to another.
#[test]
fn apply_snapshot() -> Result<()> {
    use namada_node::tendermint::abci::{
        request as tm_request, response as tm_response,
    };
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";

    let (mut node, _services) = setup::setup()?;
    {
        let mut locked = node.shell.lock().unwrap();
        locked.blocks_between_snapshots =
            Some(NonZeroU64::try_from(10_000u64).unwrap());
    }
    for _ in 0..3 {
        node.next_epoch();
    }
    let tx_args = apply_use_device(vec![
        "transparent-transfer",
        "--source",
        BERTHA,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "1234",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_one_rpc,
        "--force",
    ]);

    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    let args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, args));
    assert!(captured.contains("1981234"));

    // DB must be flushed before checkpoint
    namada_sdk::state::DB::flush(node.shell.lock().unwrap().state.db(), true)
        .unwrap();

    let base_dir = node.test_dir.path();
    let db = namada_node::storage::open(node.db_path(), true, None)
        .expect("Could not open DB");
    let last_height = node.block_height();
    let snapshot = db
        .checkpoint(base_dir.to_path_buf(), last_height)
        .expect("Test failed");
    snapshot.package().expect("Test failed");
    DbSnapshot::cleanup(last_height, base_dir, 1).expect("Test failed");

    let (node2, _services) = setup::setup()?;
    let (offer, resp) = {
        let shell = node.shell.lock().unwrap();
        let offer =
            shell.list_snapshots().snapshots.pop().expect("Test failed");
        let mut shell = node2.shell.lock().unwrap();
        (
            offer.clone(),
            shell.offer_snapshot(tm_request::OfferSnapshot {
                snapshot: offer,
                app_hash: Default::default(),
            }),
        )
    };

    assert_eq!(tm_response::OfferSnapshot::Accept, resp);
    {
        let shell = node.shell.lock().unwrap();
        let mut shell2 = node2.shell.lock().unwrap();
        for c in 0..offer.chunks {
            let chunk =
                shell.load_snapshot_chunk(tm_request::LoadSnapshotChunk {
                    height: (last_height.0 as u32).into(),
                    format: 0,
                    chunk: c,
                });
            let resp =
                shell2.apply_snapshot_chunk(tm_request::ApplySnapshotChunk {
                    index: c,
                    chunk: chunk.chunk,
                    sender: "".to_string(),
                });
            assert_eq!(
                resp,
                tm_response::ApplySnapshotChunk {
                    result: ApplySnapshotChunkResult::Accept,
                    refetch_chunks: vec![],
                    reject_senders: vec![],
                }
            );
        }
    }
    let (app_hash1, app_hash2) = {
        (
            node.shell.lock().unwrap().state.in_mem().merkle_root(),
            node2.shell.lock().unwrap().state.in_mem().merkle_root(),
        )
    };
    assert_eq!(app_hash1, app_hash2);
    let args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let captured = CapturedOutput::of(|| run(&node2, Bin::Client, args));
    assert!(captured.contains("1981234"));

    Ok(())
}

/// Test the various failure conditions of state sync
#[test]
fn snapshot_unhappy_flows() -> Result<()> {
    use namada_node::tendermint::abci::{
        request as tm_request, response as tm_response,
    };
    let (node, _services) = setup::setup()?;

    // test we abort if not syncing
    let resp = {
        let mut shell = node.shell.lock().unwrap();
        shell.apply_snapshot_chunk(tm_request::ApplySnapshotChunk {
            index: 0,
            chunk: Default::default(),
            sender: "".to_string(),
        })
    };
    assert_eq!(
        resp,
        tm_response::ApplySnapshotChunk {
            result: ApplySnapshotChunkResult::Abort,
            refetch_chunks: vec![],
            reject_senders: vec![],
        }
    );

    {
        let mut locked = node.shell.lock().unwrap();
        locked.syncing = Some(SnapshotSync {
            next_chunk: 0,
            height: Default::default(),
            expected: vec![Default::default()],
            strikes: 0,
            snapshot: tempfile::tempfile().unwrap(),
        });
    }

    // test we reject and re-fetch if the wrong chunk is given
    let resp = {
        let mut shell = node.shell.lock().unwrap();
        shell.apply_snapshot_chunk(tm_request::ApplySnapshotChunk {
            index: 1,
            chunk: Default::default(),
            sender: "".to_string(),
        })
    };
    assert_eq!(
        resp,
        tm_response::ApplySnapshotChunk {
            result: ApplySnapshotChunkResult::Unknown,
            refetch_chunks: vec![0],
            reject_senders: vec![],
        }
    );
    // test we refetch a chunk if the hash is wrong up to five times.
    for _ in 0..4 {
        let resp = {
            let mut shell = node.shell.lock().unwrap();
            shell.apply_snapshot_chunk(tm_request::ApplySnapshotChunk {
                index: 0,
                chunk: Default::default(),
                sender: "".to_string(),
            })
        };
        assert_eq!(
            resp,
            tm_response::ApplySnapshotChunk {
                result: ApplySnapshotChunkResult::Retry,
                refetch_chunks: vec![0],
                reject_senders: vec![],
            }
        );
    }
    let resp = {
        let mut shell = node.shell.lock().unwrap();
        shell.apply_snapshot_chunk(tm_request::ApplySnapshotChunk {
            index: 0,
            chunk: Default::default(),
            sender: "satan".to_string(),
        })
    };
    assert_eq!(
        resp,
        tm_response::ApplySnapshotChunk {
            result: ApplySnapshotChunkResult::RejectSnapshot,
            refetch_chunks: vec![],
            reject_senders: vec!["satan".to_string()],
        }
    );

    Ok(())
}

/// Test that a scheduled migration actually makes changes
/// to storage at the scheduled height.
#[test]
fn scheduled_migration() -> Result<()> {
    let (node, _services) = setup::setup()?;

    // schedule a migration
    let (hash, migrations_file) = make_migration_json();
    let scheduled_migration = migrations::ScheduledMigration::from_path(
        migrations_file.path(),
        hash,
        5.into(),
    )
    .expect("Test failed");
    {
        let mut locked = node.shell.lock().unwrap();
        locked.scheduled_migration = Some(scheduled_migration);
    }

    while node.last_block_height().0 != 4 {
        node.finalize_and_commit(None)
    }
    // check that the key doesn't exist before the scheduled block
    let rt = tokio::runtime::Runtime::new().unwrap();
    let bytes = rt
        .block_on(RPC.shell().storage_value(
            &node,
            None,
            None,
            false,
            &Key::parse("bing/fucking/bong").expect("Test failed"),
        ))
        .expect("Test failed")
        .data;
    assert!(bytes.is_empty());

    // check that the key now exists and has the expected value
    node.finalize_and_commit(None);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let bytes = rt
        .block_on(RPC.shell().storage_value(
            &node,
            None,
            None,
            false,
            &Key::parse("bing/fucking/bong").expect("Test failed"),
        ))
        .expect("Test failed")
        .data;
    let amount = token::Amount::try_from_slice(&bytes).expect("Test failed");
    assert_eq!(amount, token::Amount::native_whole(1337));

    // check that no migration is scheduled
    {
        let locked = node.shell.lock().unwrap();
        assert!(locked.scheduled_migration.is_none());
    }
    Ok(())
}

/// Test that a raw transaction can be wrapped and signed by someone else who
/// can pay for the gas fees for this tx.
///
/// 1. Create a new account
/// 2. Credit the new account with some tokens to reveal its PK and have tiny
///    amount left
/// 3. Reveal the PK of the new account
/// 4. Check that the new account doesn't have sufficient balance to submit a
///    transfer tx
/// 5. Dump a raw tx of a transfer from the new account
/// 6. Sign the raw transaction
/// 7. Wrap the raw transaction by another account and submit it
#[test]
fn wrap_tx_by_elsewho() -> Result<()> {
    let (node, _services) = setup::setup()?;

    // 1. Create a new account
    let key_alias = "new-account";
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Wallet,
            vec!["gen", "--alias", key_alias, "--unsafe-dont-encrypt"],
        )
    });
    assert!(captured.result.is_ok());

    // 2. Credit the new account with some tokens to reveal its PK and have tiny
    //    amount left
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                ALBERT,
                "--target",
                key_alias,
                "--token",
                NAM,
                "--amount",
                // transfer enough to cover reveal-pk gas fees (0.5) and to
                // have only 0.000001 left after
                "0.500001",
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 3. Reveal the PK of the new account
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "reveal-pk",
                "--public-key",
                key_alias,
                "--gas-payer",
                key_alias,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Assert that there's only the smallest possible non-zero amount left
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec!["balance", "--owner", key_alias, "--token", NAM],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.000001"));

    // 4. Check that the new account doesn't have sufficient balance to submit a
    //    transfer tx
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                key_alias,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "0.000001",
            ]),
        )
    });
    assert!(captured.result.is_err());
    assert_matches!(
        captured
            .result
            .unwrap_err()
            .downcast_ref::<namada_sdk::error::Error>()
            .unwrap(),
        namada_sdk::error::Error::Tx(TxSubmitError::BalanceTooLowForFees(
            _,
            _,
            _,
            _
        ))
    );

    // 5. Dump a raw tx of a transfer from the new account
    let output_folder = node.test_dir.path();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                key_alias,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "0.000001",
                // Force to ignore the balance check
                "--force",
                "--dump-tx",
                "--output-folder-path",
                &output_folder.to_str().unwrap(),
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let tx = find_files_with_ext(output_folder, "tx")
        .unwrap()
        .first()
        .expect("Offline tx should be found.")
        .to_path_buf()
        .display()
        .to_string();

    // 6. Sign the raw transaction
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "utils",
                "sign-offline",
                "--data-path",
                &tx,
                "--secret-keys",
                &key_alias,
                "--output-folder-path",
                &output_folder.to_str().unwrap(),
            ],
        )
    });
    assert!(captured.result.is_ok());

    let sig_files = find_files_with_ext(output_folder, "sig").unwrap();
    assert_eq!(sig_files.len(), 1);
    let offline_sig = sig_files.first().unwrap().to_str().unwrap();

    // 7. Wrap the raw transaction by another account and submit it
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "tx",
                "--tx-path",
                &tx,
                "--signatures",
                &offline_sig,
                "--gas-payer",
                CHRISTEL_KEY,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Assert changed balances
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec!["balance", "--owner", ALBERT, "--token", NAM],
        )
    });
    assert!(captured.contains("nam: 1979999.5\n"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec!["balance", "--owner", key_alias, "--token", NAM],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0\n"));

    Ok(())
}

/// Test that a raw transaction can be wrapped and signed by someone else who
/// can pay for the gas fees for this tx.
///
/// 1. Create a new account
/// 2. Credit the new account with some tokens to reveal its PK and have tiny
///    amount left
/// 3. Reveal the PK of the new account
/// 4. Check that the new account doesn't have sufficient balance to submit a
///    transfer tx
/// 5. Dump a raw tx of a transfer from the new account
/// 6. Sign the raw transaction
/// 7. Wrap the raw transaction by another account
/// 8. Offline sign the wrapper
/// 9. Load the dumped wrapper with the signatures and submit it
#[test]
fn offline_wrap_tx_by_elsewho() -> Result<()> {
    let (node, _services) = setup::setup()?;

    // 1. Create a new account
    let key_alias = "new-account";
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Wallet,
            vec!["gen", "--alias", key_alias, "--unsafe-dont-encrypt"],
        )
    });
    assert!(captured.result.is_ok());

    // 2. Credit the new account with some tokens to reveal its PK and have tiny
    //    amount left
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                ALBERT,
                "--target",
                key_alias,
                "--token",
                NAM,
                "--amount",
                // transfer enough to cover reveal-pk gas fees (0.5) and to
                // have only 0.000001 left after
                "0.500001",
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 3. Reveal the PK of the new account
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "reveal-pk",
                "--public-key",
                key_alias,
                "--gas-payer",
                key_alias,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Assert that there's only the smallest possible non-zero amount left
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec!["balance", "--owner", key_alias, "--token", NAM],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.000001"));

    // 4. Check that the new account doesn't have sufficient balance to submit a
    //    transfer tx
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                key_alias,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "0.000001",
            ]),
        )
    });
    assert!(captured.result.is_err());
    assert_matches!(
        captured
            .result
            .unwrap_err()
            .downcast_ref::<namada_sdk::error::Error>()
            .unwrap(),
        namada_sdk::error::Error::Tx(TxSubmitError::BalanceTooLowForFees(
            _,
            _,
            _,
            _
        ))
    );

    // 5. Dump a raw tx of a transfer from the new account
    let output_folder = node.test_dir.path();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                key_alias,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "0.000001",
                "--force",
                "--dump-tx",
                "--output-folder-path",
                &output_folder.to_str().unwrap(),
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let tx_path_buf = find_files_with_ext(output_folder, "tx")
        .unwrap()
        .first()
        .expect("Offline tx should be found.")
        .to_owned();
    let tx = tx_path_buf.to_path_buf().display().to_string();

    // 6. Sign the raw transaction
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "utils",
                "sign-offline",
                "--data-path",
                &tx,
                "--secret-keys",
                &key_alias,
                "--output-folder-path",
                &output_folder.to_str().unwrap(),
            ],
        )
    });
    assert!(captured.result.is_ok());

    let sig_files = find_files_with_ext(output_folder, "sig").unwrap();
    assert_eq!(sig_files.len(), 1);
    let offline_sig_path = sig_files.first().unwrap();
    let offline_sig = offline_sig_path.to_str().unwrap();

    // 7. Wrap the raw transaction by another account and dump the wrapper
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "tx",
                "--tx-path",
                &tx,
                "--signatures",
                &offline_sig,
                "--gas-payer",
                CHRISTEL_KEY,
                "--dump-wrapper-tx",
                "--output-folder-path",
                &output_folder.to_str().unwrap(),
            ]),
        )
    });
    assert!(captured.result.is_ok());
    let wrapper_tx = find_files_with_ext(output_folder, "tx")
        .unwrap()
        .into_iter()
        .find(|wrapper_tx| wrapper_tx != &tx_path_buf)
        .expect("Offline wrapper tx should be found.")
        .to_path_buf()
        .display()
        .to_string();

    // 8. Sign the wrapper offline
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "utils",
                "sign-offline",
                "--data-path",
                &wrapper_tx,
                "--secret-key",
                CHRISTEL_KEY,
                "--output-folder-path",
                &output_folder.to_str().unwrap(),
            ],
        )
    });
    assert!(captured.result.is_ok());

    let sig_files = find_files_with_ext(output_folder, "sig").unwrap();
    assert_eq!(sig_files.len(), 2);
    let offline_wrapper_sig = sig_files
        .into_iter()
        .find(|wrapper_sig| wrapper_sig != offline_sig_path)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    // 9. Submit the wrapped tx
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "tx",
                "--tx-path",
                &wrapper_tx,
                // We've attached the inner signatures to the tx when we
                // wrapped it, so we only need to provide the wrapper signature
                // here
                "--gas-signature",
                &offline_wrapper_sig,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Assert changed balances
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec!["balance", "--owner", ALBERT, "--token", NAM],
        )
    });
    assert!(captured.contains("nam: 1979999.5\n"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec!["balance", "--owner", key_alias, "--token", NAM],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0\n"));

    Ok(())
}

/// Test that a wrapper transaction can be dumped and later signed offline.
///
/// 1. Create a new account
/// 2. Credit the new account with some tokens to reveal its PK and have tiny
///    amount left
/// 3. Reveal the PK of the new account
/// 4. Check that the new account doesn't have sufficient balance to submit a
///    transfer tx
/// 5. Dump a wrapper tx of a transfer from the new account
/// 6. Sign both the wrapper and raw transaction
/// 7. Load the dumped wrapper with the signatures and submit it
#[test]
fn offline_wrapper_tx() -> Result<()> {
    let (node, _services) = setup::setup()?;

    // 1. Create a new account
    let key_alias = "new-account";
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Wallet,
            vec!["gen", "--alias", key_alias, "--unsafe-dont-encrypt"],
        )
    });
    assert!(captured.result.is_ok());

    // 2. Credit the new account with some tokens to reveal its PK and have tiny
    //    amount left
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                ALBERT,
                "--target",
                key_alias,
                "--token",
                NAM,
                "--amount",
                // transfer enough to cover reveal-pk gas fees (0.5) and to
                // have only 0.000001 left after
                "0.500001",
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 3. Reveal the PK of the new account
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "reveal-pk",
                "--public-key",
                key_alias,
                "--gas-payer",
                key_alias,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Assert that there's only the smallest possible non-zero amount left
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec!["balance", "--owner", key_alias, "--token", NAM],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.000001"));

    // 4. Check that the new account doesn't have sufficient balance to submit a
    //    transfer tx
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                key_alias,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "0.000001",
            ]),
        )
    });
    assert!(captured.result.is_err());
    assert_matches!(
        captured
            .result
            .unwrap_err()
            .downcast_ref::<namada_sdk::error::Error>()
            .unwrap(),
        namada_sdk::error::Error::Tx(TxSubmitError::BalanceTooLowForFees(
            _,
            _,
            _,
            _
        ))
    );

    // 5. Dump a wrapper tx of a transfer from the new account
    let output_folder = node.test_dir.path();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                key_alias,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "0.000001",
                "--gas-payer",
                CHRISTEL_KEY,
                "--dump-wrapper-tx",
                "--output-folder-path",
                &output_folder.to_str().unwrap(),
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let tx_path_buf = find_files_with_ext(output_folder, "tx")
        .unwrap()
        .first()
        .expect("Offline tx should be found.")
        .to_owned();
    let tx = tx_path_buf.to_path_buf().display().to_string();

    // 6. Sign both the wrapper and raw transaction
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "utils",
                "sign-offline",
                "--data-path",
                &tx,
                "--secret-keys",
                &key_alias,
                "--secret-key",
                CHRISTEL_KEY,
                "--output-folder-path",
                &output_folder.to_str().unwrap(),
            ],
        )
    });
    assert!(captured.result.is_ok());

    let sig_files = find_files_with_ext(output_folder, "sig").unwrap();
    assert_eq!(sig_files.len(), 2);

    let offline_sig = sig_files
        .iter()
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("offline_signature")
        })
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let offline_wrapper_sig = sig_files
        .iter()
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("offline_wrapper_signature")
        })
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    // 7. Submit the wrapped tx
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "tx",
                "--tx-path",
                &tx,
                "--signatures",
                &offline_sig,
                "--gas-signature",
                &offline_wrapper_sig,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Assert changed balances
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec!["balance", "--owner", ALBERT, "--token", NAM],
        )
    });
    assert!(captured.contains("nam: 1979999.5\n"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec!["balance", "--owner", key_alias, "--token", NAM],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0\n"));

    Ok(())
}

/// Test for PoS validator metadata validation.
///
/// 1. Run the ledger node.
/// 2. Submit a valid metadata change tx.
/// 3. Check that the metadata has changed.
/// 4. Submit an invalid metadata change tx.
/// 5. Check that the metadata has not changed.
/// 6. Submit a tx to become validator with invalid metadata.
#[test]
fn pos_validator_metadata_validation() -> Result<()> {
    // 1. Run the ledger node.
    let (node, _services) = setup::setup()?;

    // 2. Submit a valid metadata change tx.
    let valid_desc: String = "0123456789".repeat(50);
    assert_eq!(valid_desc.len() as u64, MAX_VALIDATOR_METADATA_LEN);
    let tx_args = apply_use_device(vec![
        "change-metadata",
        "--validator",
        "validator-0-validator",
        "--description",
        &valid_desc,
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    println!("{:?}", captured.result);
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 3. Check that the metadata has changed.
    let query_args =
        vec!["validator-metadata", "--validator", "validator-0-validator"];
    let captured =
        CapturedOutput::of(|| run(&node, Bin::Client, query_args.clone()));
    println!("{:?}", captured.result);
    assert!(captured.contains(&valid_desc));

    // 4. Submit an invalid metadata change tx.
    let invalid_desc: String = format!("N{valid_desc}");
    assert!(invalid_desc.len() as u64 > MAX_VALIDATOR_METADATA_LEN);
    let tx_args = apply_use_device(vec![
        "change-metadata",
        "--validator",
        "validator-0-validator",
        "--description",
        &invalid_desc,
        "--force",
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    println!("{:?}", captured.result);
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_REJECTED));

    // 5. Check that the metadata has not changed.
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, query_args));
    println!("{:?}", captured.result);
    assert!(captured.contains(&valid_desc));

    // 6. Submit a tx to become validator with invalid metadata.
    let new_validator = "new-validator";
    let tx_args = apply_use_device(vec![
        "init-validator",
        "--alias",
        new_validator,
        "--name",
        new_validator,
        "--account-keys",
        "bertha-key",
        "--commission-rate",
        "0.05",
        "--max-commission-rate-change",
        "0.01",
        "--email",
        "null@null.net",
        "--signing-keys",
        "bertha-key",
        "--description",
        &invalid_desc,
        "--unsafe-dont-encrypt",
    ]);
    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Err(_));
    assert!(captured.contains(TX_REJECTED));

    Ok(())
}

// Test that a client can reconstruct the events associated with a transaction
#[test]
fn client_events_reconstruction() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    let (node, _services) = setup::setup()?;

    // Submit a transfer transaction that will emit a transfer event
    let tx_args = apply_use_device(vec![
        "transparent-transfer",
        "--source",
        BERTHA_KEY,
        "--target",
        ALBERT_KEY,
        "--token",
        NAM,
        "--amount",
        "1",
        "--node",
        &validator_one_rpc,
        "--force",
    ]);

    let captured = CapturedOutput::of(|| run(&node, Bin::Client, tx_args));
    assert_matches!(captured.result, Ok(_));
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    // Check that, even if we don't serialize the events within the tx/applied
    // event, the client can recover the events associated with this transaction
    // from the block and reconstruct a complete log for the user
    assert!(captured.contains("Events:"));
    assert!(captured.contains("- tx - token/transfer:"));

    Ok(())
}

fn make_migration_json() -> (Hash, tempfile::NamedTempFile) {
    let file = tempfile::Builder::new().tempfile().expect("Test failed");
    let updates = [migrations::DbUpdateType::Add {
        key: Key::parse("bing/fucking/bong").expect("Test failed"),
        cf: DbColFam::SUBSPACE,
        value: token::Amount::native_whole(1337).into(),
        force: false,
    }];
    let changes = migrations::DbChanges {
        changes: updates.into_iter().collect(),
    };
    let json = serde_json::to_string(&changes).expect("Test failed");
    let hash = Hash::sha256(json.as_bytes());
    std::fs::write(file.path(), json).expect("Test failed");
    (hash, file)
}

pub fn find_files_with_ext(
    dir: &Path,
    extension: &str,
) -> Result<Vec<PathBuf>> {
    let mut result = vec![];

    // Read the directory entries
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(file_extension) = path.extension() {
                if file_extension == extension {
                    result.push(path);
                }
            }
        }
    }

    Ok(result)
}
