use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::I128Sum;
use namada_apps_lib::wallet::defaults::{
    get_unencrypted_keypair, is_use_device,
};
use namada_core::address::Address;
use namada_core::dec::Dec;
use namada_core::masp::{MaspTxId, Precision, TokenMap, encode_asset_type};
use namada_node::shell::ResultCode;
use namada_node::shell::testing::client::run;
use namada_node::shell::testing::node::NodeResults;
use namada_node::shell::testing::utils::{Bin, CapturedOutput};
use namada_sdk::account::AccountPublicKeysMap;
#[cfg(feature = "historic-masp")]
use namada_sdk::collections::HashMap;
use namada_sdk::masp::fs::FsShieldedUtils;
use namada_sdk::signing::{
    FeeAuthorization, SigningData, SigningTxData, SigningWrapperData,
};
use namada_sdk::state::{StorageRead, StorageWrite};
use namada_sdk::time::DateTimeUtc;
use namada_sdk::token::storage_key::{
    masp_base_native_precision_key, masp_conversion_key,
    masp_reward_precision_key, masp_scheduled_base_native_precision_key,
    masp_scheduled_reward_precision_key, masp_token_map_key,
};
use namada_sdk::token::{self, Amount, DenominatedAmount, MaspEpoch};
#[cfg(feature = "historic-masp")]
use namada_sdk::tx::IndexedTx;
use namada_sdk::tx::{Section, Tx};
use namada_sdk::{DEFAULT_GAS_LIMIT, tx};
use test_log::test;

use super::{helpers, setup};
use crate::e2e::setup::apply_use_device;
use crate::e2e::setup::constants::{
    A_SPENDING_KEY, AA_PAYMENT_ADDRESS, AA_VIEWING_KEY, AB_PAYMENT_ADDRESS,
    AB_VIEWING_KEY, AC_PAYMENT_ADDRESS, AC_VIEWING_KEY, ALBERT, ALBERT_KEY,
    B_SPENDING_KEY, BB_PAYMENT_ADDRESS, BERTHA, BERTHA_KEY, BTC,
    C_SPENDING_KEY, CHRISTEL, CHRISTEL_KEY, ETH, FRANK_KEY, MASP, NAM,
};
use crate::integration::helpers::make_temp_account;
use crate::strings::TX_APPLIED_SUCCESS;

/// Enable masp rewards before some token is shielded,
/// but the max reward rate is null.
#[test]
fn init_null_rewards() -> Result<()> {
    // Dummy validator rpc address
    const RPC: &str = "http://127.0.0.1:26567";

    // We will mint tokens with this address
    const TEST_TOKEN_ADDR: &str =
        "tnam1q9382etwdaekg6tpwdkkzar0wd5ku6r0wvu5ukqd";
    let test_token_addr: Address = TEST_TOKEN_ADDR.parse().unwrap();

    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    // Boot up a mock node
    let (mut node, _services) = setup::setup()?;

    // Initialize the test token
    token::write_denom(
        &mut node.shell.lock().unwrap().state,
        &test_token_addr,
        0u8.into(),
    )?;

    // Give Bertha some test tokens
    let bertha_addr = helpers::find_address(&node, BERTHA)?;
    token::credit_tokens(
        &mut node.shell.lock().unwrap().state,
        &test_token_addr,
        &bertha_addr,
        Amount::from_u64(1_000_000_000u64),
    )?;

    // Commit test token changes to a new block
    node.finalize_and_commit(None);
    assert_eq!(
        token::read_total_supply(
            &node.shell.lock().unwrap().state,
            &test_token_addr,
        )?,
        Amount::from_u64(1_000_000_000u64),
    );

    // Initialize the token map with the test
    // token, and set the test token's max
    // reward rate to 0
    token::write_params(
        &Some(token::ShieldedParams {
            max_reward_rate: Dec::from_str("0").unwrap(),
            kp_gain_nom: Dec::from_str("0").unwrap(),
            kd_gain_nom: Dec::from_str("0").unwrap(),
            locked_amount_target: 0,
        }),
        &mut node.shell.lock().unwrap().state,
        &test_token_addr,
        &0u8.into(),
    )?;
    let mut token_map =
        token::read_token_map(&node.shell.lock().unwrap().state)?;
    token_map.insert("TEST".to_owned(), test_token_addr.clone());
    token::write_token_map(&mut node.shell.lock().unwrap().state, token_map)?;
    node.finalize_and_commit(None);

    // Cross a new masp epoch, to allow the conversion
    // state to update itself
    node.next_masp_epoch();

    // Shield test tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                BERTHA,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                TEST_TOKEN_ADDR,
                "--amount",
                "1000000",
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch the latest test token notes
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check that we have some shielded test tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("{TEST_TOKEN_ADDR}: 1000000")));

    // Skip a couple of masp epochs
    for _ in 0..3 {
        node.next_masp_epoch();
    }

    // Assert that we have no NAM rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains("nam: 0"));

    // Now, let us increase the max reward rate
    token::write_params(
        &Some(token::ShieldedParams {
            max_reward_rate: Dec::from_str("1.0").unwrap(),
            kp_gain_nom: Dec::from_str("9999999999").unwrap(),
            kd_gain_nom: Dec::from_str("9999999999").unwrap(),
            locked_amount_target: 999999999u64,
        }),
        &mut node.shell.lock().unwrap().state,
        &test_token_addr,
        &0u8.into(),
    )?;
    node.finalize_and_commit(None);

    // We shouldn't have any NAM rewards yet, not
    // until we cross another masp epoch
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains("nam: 0"));

    // Skip to the next masp epoch
    node.next_masp_epoch();

    // Assert that we have minted NAM rewards
    const EXPECTED_REWARDS: u128 = 7;
    const UNSHIELD_REWARDS_AMT: u128 = EXPECTED_REWARDS / 2;
    const REMAINING_REWARDS_AMT: u128 = EXPECTED_REWARDS - UNSHIELD_REWARDS_AMT;

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("nam: {EXPECTED_REWARDS}")));

    // Unshield half of the rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                &UNSHIELD_REWARDS_AMT.to_string(),
                "--signing-keys",
                BERTHA_KEY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch latest shielded state
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check that we now have half of the rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("nam: {REMAINING_REWARDS_AMT}")));

    // Transfer the other half of the rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                &REMAINING_REWARDS_AMT.to_string(),
                "--signing-keys",
                BERTHA_KEY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch latest shielded state
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check that we now a null NAM balance
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains("nam: 0"));

    // Unshield half of our test tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                TEST_TOKEN_ADDR,
                "--amount",
                "500000",
                "--signing-keys",
                BERTHA_KEY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch latest shielded state
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check test token balance
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("{TEST_TOKEN_ADDR}: 500000")));

    Ok(())
}

/// Test interacting with masp amounts that span more than 64 bits.
#[test]
fn values_spanning_multiple_masp_digits() -> Result<()> {
    // Dummy validator rpc address
    const RPC: &str = "http://127.0.0.1:26567";

    // We will mint tokens with this address
    const TEST_TOKEN_ADDR: &str =
        "tnam1q9382etwdaekg6tpwdkkzar0wd5ku6r0wvu5ukqd";
    let test_token_addr: Address = TEST_TOKEN_ADDR.parse().unwrap();

    const TEST_TOKEN_INITIAL_SUPPLY: &str = "6427858447239330000000";
    const HALF_TEST_TOKEN_INITIAL_SUPPLY: &str = "3213929223619665000000";
    let test_token_initial_supply = {
        let supply: DenominatedAmount =
            TEST_TOKEN_INITIAL_SUPPLY.parse().unwrap();
        assert_eq!(supply.denom(), 0u8.into());
        supply.amount()
    };

    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    // Boot up a mock node
    let (mut node, _services) = setup::setup()?;

    // Initialize the test token
    token::write_denom(
        &mut node.shell.lock().unwrap().state,
        &test_token_addr,
        0u8.into(),
    )?;

    // Give Bertha some test tokens
    let bertha_addr = helpers::find_address(&node, BERTHA)?;
    token::credit_tokens(
        &mut node.shell.lock().unwrap().state,
        &test_token_addr,
        &bertha_addr,
        test_token_initial_supply,
    )?;

    // Commit test token changes to a new block
    node.finalize_and_commit(None);
    assert_eq!(
        token::read_total_supply(
            &node.shell.lock().unwrap().state,
            &test_token_addr,
        )?,
        test_token_initial_supply,
    );

    // Shield HALF_TEST_TOKEN_INITIAL_SUPPLY test tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                BERTHA,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                TEST_TOKEN_ADDR,
                "--amount",
                HALF_TEST_TOKEN_INITIAL_SUPPLY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch the note we just created containing test tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check the test token balance corresponds 1:1 to what
    // we shielded
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!(
        "{TEST_TOKEN_ADDR}: {HALF_TEST_TOKEN_INITIAL_SUPPLY}"
    )));

    // Skip a couple of masp epochs
    for _ in 0..3 {
        node.next_masp_epoch();
    }

    // Assert that these assets are not receiving rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains("nam: 0"));

    // Unshield the test tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                TEST_TOKEN_ADDR,
                "--amount",
                HALF_TEST_TOKEN_INITIAL_SUPPLY,
                "--signing-keys",
                BERTHA_KEY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Run shielded sync
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check test token balance is null
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("{TEST_TOKEN_ADDR}: 0")));

    // Let's enable NAM rewards, to test their interaction
    // with multiple notes. In practice, if we have shielded
    // some token amount that spans more than 64 bits, we are
    // probably dealing with an incredibly shitty coin. It is
    // wise to check that no crashes occur from conversions,
    // though.
    token::write_params(
        &Some(token::ShieldedParams {
            // NB: the max reward rate needs to be quite big, to allow
            // the inflation being computed by the pd controller to
            // exceed the amount of test tokens in the masp
            max_reward_rate: Dec::from_str("999999999999999.0").unwrap(),
            kp_gain_nom: Dec::from_str("99999999999999999999").unwrap(),
            kd_gain_nom: Dec::from_str("99999999999999999999").unwrap(),
            locked_amount_target: u64::MAX,
        }),
        &mut node.shell.lock().unwrap().state,
        &test_token_addr,
        &0u8.into(),
    )?;
    let mut token_map =
        token::read_token_map(&node.shell.lock().unwrap().state)?;
    token_map.insert("TEST".to_owned(), test_token_addr.clone());
    token::write_token_map(&mut node.shell.lock().unwrap().state, token_map)?;
    node.finalize_and_commit(None);

    // Cross a new masp epoch, to allow the conversion
    // state to update itself
    node.next_masp_epoch();

    // Shield HALF_TEST_TOKEN_INITIAL_SUPPLY test tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                BERTHA,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                TEST_TOKEN_ADDR,
                "--amount",
                HALF_TEST_TOKEN_INITIAL_SUPPLY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch the note we just created containing test tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check the test token balance
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!(
        "{TEST_TOKEN_ADDR}: {HALF_TEST_TOKEN_INITIAL_SUPPLY}"
    )));

    // Skip a couple of masp epochs
    for _ in 0..3 {
        node.next_masp_epoch();
    }

    // Assert that we have minted NAM rewards
    const EXPECTED_REWARDS: u128 = 6427858447239330;
    const UNSHIELD_REWARDS_AMT: u128 = EXPECTED_REWARDS / 2;
    const REMAINING_REWARDS_AMT: u128 = EXPECTED_REWARDS - UNSHIELD_REWARDS_AMT;

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("nam: {EXPECTED_REWARDS}")));

    // Unshield half of the rewards. Pay for gas transparently
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                &UNSHIELD_REWARDS_AMT.to_string(),
                "--gas-payer",
                BERTHA_KEY,
                "--node",
                RPC,
                "--gas-limit",
                "65000",
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch latest shielded state
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check that we now have half of the rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("nam: {REMAINING_REWARDS_AMT}")));

    // Shield 1 NAM to cover fees
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                BERTHA_KEY,
                "--target",
                AC_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-payer",
                BERTHA_KEY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch latest shielded state
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AC_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check the shielded NAM balance
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AC_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains("nam: 1"));

    // Unshield the other half of the rewards. Pay for gas using
    // a spending key
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                &REMAINING_REWARDS_AMT.to_string(),
                "--node",
                RPC,
                "--gas-spending-key",
                C_SPENDING_KEY,
                "--gas-limit",
                "65000",
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch latest shielded state
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AC_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check that we now have a null NAM balance
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains("nam: 0"));

    Ok(())
}

/// Enable masp rewards after some token had already been shielded.
#[test]
fn enable_rewards_after_shielding() -> Result<()> {
    // Dummy validator rpc address
    const RPC: &str = "http://127.0.0.1:26567";

    // We will mint tokens with this address
    const TEST_TOKEN_ADDR: &str =
        "tnam1q9382etwdaekg6tpwdkkzar0wd5ku6r0wvu5ukqd";
    let test_token_addr: Address = TEST_TOKEN_ADDR.parse().unwrap();

    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    // Boot up a mock node
    let (mut node, _services) = setup::setup()?;

    // Initialize the test token
    token::write_denom(
        &mut node.shell.lock().unwrap().state,
        &test_token_addr,
        0u8.into(),
    )?;

    // Give Bertha some test tokens
    let bertha_addr = helpers::find_address(&node, BERTHA)?;
    token::credit_tokens(
        &mut node.shell.lock().unwrap().state,
        &test_token_addr,
        &bertha_addr,
        Amount::from_u64(1_000_000_000u64),
    )?;

    // Commit test token changes to a new block
    node.finalize_and_commit(None);
    assert_eq!(
        token::read_total_supply(
            &node.shell.lock().unwrap().state,
            &test_token_addr,
        )?,
        Amount::from_u64(1_000_000_000u64),
    );

    // Shield 1_000_000 test tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                BERTHA,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                TEST_TOKEN_ADDR,
                "--amount",
                "1000000",
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch the note we just created containing test tokens
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check the test token balance corresponds 1:1 to what
    // we shielded
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("{TEST_TOKEN_ADDR}: 1000000")));

    // Skip a couple of masp epochs
    for _ in 0..3 {
        node.next_masp_epoch();
    }

    // The balance shouldn't have changed
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("{TEST_TOKEN_ADDR}: 1000000")));

    // Check that our NAM balance is null
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains("nam: 0"));

    // Let us now start minting NAM rewards for any
    // test tokens in the shielded pool
    token::write_params(
        &Some(token::ShieldedParams {
            max_reward_rate: Dec::from_str("1.0").unwrap(),
            kp_gain_nom: Dec::from_str("9999999999").unwrap(),
            kd_gain_nom: Dec::from_str("9999999999").unwrap(),
            locked_amount_target: 999999999u64,
        }),
        &mut node.shell.lock().unwrap().state,
        &test_token_addr,
        &0u8.into(),
    )?;
    let mut token_map =
        token::read_token_map(&node.shell.lock().unwrap().state)?;
    token_map.insert("TEST".to_owned(), test_token_addr.clone());
    token::write_token_map(&mut node.shell.lock().unwrap().state, token_map)?;
    node.finalize_and_commit(None);

    // Skip a couple of masp epochs
    for _ in 0..3 {
        node.next_masp_epoch();
    }

    // We won't have any NAM rewards yet, because our
    // test tokens weren't tagged with an epoch
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("{TEST_TOKEN_ADDR}: 1000000")));

    // Check that our NAM balance is null
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains("nam: 0"));

    // Unshield and reshield some test tokens, such that they
    // are now tagged with a masp epoch
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                TEST_TOKEN_ADDR,
                "--amount",
                "1000000",
                "--signing-keys",
                BERTHA_KEY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch the latest test token notes
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check that the balance is now 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("{TEST_TOKEN_ADDR}: 0")));

    // Update the conversion state
    node.next_masp_epoch();

    // Reshield
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                BERTHA,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                TEST_TOKEN_ADDR,
                "--amount",
                "1000000",
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch the latest test token notes
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check that we have some shielded test tokens once more
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("{TEST_TOKEN_ADDR}: 1000000")));

    // We won't have any rewards yet
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains("nam: 0"));

    // Skip a couple of masp epochs
    for _ in 0..3 {
        node.next_masp_epoch();
    }

    // Assert that we have minted NAM rewards
    const EXPECTED_REWARDS: u128 = 21;
    const UNSHIELD_REWARDS_AMT: u128 = EXPECTED_REWARDS / 2;
    const REMAINING_REWARDS_AMT: u128 = EXPECTED_REWARDS - UNSHIELD_REWARDS_AMT;

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("nam: {EXPECTED_REWARDS}")));

    // Unshield half of the rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                &UNSHIELD_REWARDS_AMT.to_string(),
                "--signing-keys",
                BERTHA_KEY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch latest shielded state
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check that we now have half of the rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("nam: {REMAINING_REWARDS_AMT}")));

    // Transfer the other half of the rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                &REMAINING_REWARDS_AMT.to_string(),
                "--signing-keys",
                BERTHA_KEY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch latest shielded state
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check that we now a null NAM balance
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains("nam: 0"));

    // Unshield half of our test tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                TEST_TOKEN_ADDR,
                "--amount",
                "500000",
                "--signing-keys",
                BERTHA_KEY,
                "--node",
                RPC,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Fetch latest shielded state
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            RPC,
        ],
    )?;

    // Check test token balance
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                TEST_TOKEN_ADDR,
                "--node",
                RPC,
            ],
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(&format!("{TEST_TOKEN_ADDR}: 500000")));

    Ok(())
}

/// In this test we verify that the results of auto-compounding are
/// approximately equal to what is obtained by manually unshielding and
/// reshielding each time.
#[test]
fn auto_compounding() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 0.1 BTC from Albert to Albert's payment address
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "0.1",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Send 0.1 BTC from Albert to Bertha's payment address
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "0.1",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert that the actual and estimated balances are equal to the parameters
    // of this closure. Also assert that the total MASP balance is equal to the
    // last parameter. Then unshield, reshield, synchronize, and jump to the
    // next epoch.
    let mut check_balance_and_reshield =
        |bal_a, bal_b, est_a, est_b, total| -> Result<()> {
            // Assert BTC balance at ALbert's shielded key is still 0.1
            let captured = CapturedOutput::of(|| {
                run(
                    &node,
                    Bin::Client,
                    vec![
                        "balance",
                        "--owner",
                        AA_VIEWING_KEY,
                        "--token",
                        BTC,
                        "--node",
                        validator_one_rpc,
                    ],
                )
            });
            assert!(captured.result.is_ok());
            assert!(captured.contains("btc: 0.1"));

            // Assert BTC balance at Bertha's shielded key is still 0.1
            let captured = CapturedOutput::of(|| {
                run(
                    &node,
                    Bin::Client,
                    vec![
                        "balance",
                        "--owner",
                        AB_VIEWING_KEY,
                        "--token",
                        BTC,
                        "--node",
                        validator_one_rpc,
                    ],
                )
            });
            assert!(captured.result.is_ok());
            assert!(captured.contains("btc: 0.1"));

            // Assert NAM balance at Albert's shielded key is bal_a
            let captured = CapturedOutput::of(|| {
                run(
                    &node,
                    Bin::Client,
                    vec![
                        "balance",
                        "--owner",
                        AA_VIEWING_KEY,
                        "--token",
                        NAM,
                        "--node",
                        validator_one_rpc,
                    ],
                )
            });

            assert!(captured.result.is_ok());
            assert!(captured.contains(&format!("nam: {}", bal_a)));

            // Assert NAM balance at Bertha's shielded key is bal_b
            let captured = CapturedOutput::of(|| {
                run(
                    &node,
                    Bin::Client,
                    vec![
                        "balance",
                        "--owner",
                        AB_VIEWING_KEY,
                        "--token",
                        NAM,
                        "--node",
                        validator_one_rpc,
                    ],
                )
            });

            assert!(captured.result.is_ok());
            assert!(captured.contains(&format!("nam: {}", bal_b)));

            // Assert the rewards estimate at Albert's shielded key matches
            // est_a
            let captured = CapturedOutput::of(|| {
                run(
                    &node,
                    Bin::Client,
                    vec![
                        "estimate-shielding-rewards",
                        "--key",
                        AA_VIEWING_KEY,
                        "--node",
                        validator_one_rpc,
                    ],
                )
            });
            assert!(captured.result.is_ok());
            assert!(captured.contains(&format!(
                "Estimated native token rewards for the next MASP epoch: {}",
                est_a
            )));

            // Assert the rewards estimate at Bertha's shielded key matches
            // est_b
            let captured = CapturedOutput::of(|| {
                run(
                    &node,
                    Bin::Client,
                    vec![
                        "estimate-shielding-rewards",
                        "--key",
                        AB_VIEWING_KEY,
                        "--node",
                        validator_one_rpc,
                    ],
                )
            });
            assert!(captured.result.is_ok());
            assert!(captured.contains(&format!(
                "Estimated native token rewards for the next MASP epoch: {}",
                est_b
            )));

            // Assert NAM balance at MASP pool is exclusively the
            // rewards from the shielded BTC
            let captured = CapturedOutput::of(|| {
                run(
                    &node,
                    Bin::Client,
                    vec![
                        "balance",
                        "--owner",
                        MASP,
                        "--token",
                        NAM,
                        "--node",
                        validator_one_rpc,
                    ],
                )
            });
            assert!(captured.result.is_ok());
            assert!(captured.contains(&format!("nam: {}", total)));

            // Send bal_b NAM from Bertha's shielded key to Albert
            let captured = CapturedOutput::of(|| {
                run(
                    &node,
                    Bin::Client,
                    apply_use_device(vec![
                        "unshield",
                        "--source",
                        B_SPENDING_KEY,
                        "--target",
                        ALBERT,
                        "--token",
                        NAM,
                        "--amount",
                        bal_b,
                        "--gas-limit",
                        "70000",
                        "--signing-keys",
                        ALBERT_KEY,
                        "--node",
                        validator_one_rpc,
                    ]),
                )
            });
            assert!(captured.result.is_ok());
            assert!(captured.contains(TX_APPLIED_SUCCESS));

            // sync the shielded context
            run(
                &node,
                Bin::Client,
                vec![
                    "shielded-sync",
                    "--viewing-keys",
                    AA_VIEWING_KEY,
                    AB_VIEWING_KEY,
                    "--node",
                    validator_one_rpc,
                ],
            )?;

            // Send bal_b NAM from Albert to Bertha's shielded key
            let captured = CapturedOutput::of(|| {
                run(
                    &node,
                    Bin::Client,
                    apply_use_device(vec![
                        "shield",
                        "--source",
                        ALBERT,
                        "--target",
                        AB_PAYMENT_ADDRESS,
                        "--token",
                        NAM,
                        "--amount",
                        bal_b,
                        "--signing-keys",
                        ALBERT_KEY,
                        "--node",
                        validator_one_rpc,
                    ]),
                )
            });
            assert!(captured.result.is_ok());
            assert!(captured.contains(TX_APPLIED_SUCCESS));

            // sync the shielded context
            run(
                &node,
                Bin::Client,
                vec![
                    "shielded-sync",
                    "--viewing-keys",
                    AA_VIEWING_KEY,
                    AB_VIEWING_KEY,
                    "--node",
                    validator_one_rpc,
                ],
            )?;

            // Wait till epoch boundary
            node.next_masp_epoch();

            Ok(())
        };

    // Now check that the principal amount compounds correctly over a few epochs
    check_balance_and_reshield("0", "0", "0", "0", "0")?;
    check_balance_and_reshield(
        "0.0317", "0.0317", "0.0317", "0.0317", "0.0634",
    )?;
    check_balance_and_reshield(
        "0.09534", "0.09533", "0.06491", "0.0649", "0.190688",
    )?;
    check_balance_and_reshield(
        "0.191008", "0.190982", "0.09678", "0.096796", "0.382016",
    )?;
    check_balance_and_reshield(
        "0.31854", "0.31851", "0.128528", "0.128524", "0.637092",
    )?;
    Ok(())
}

// Test that the base native precision and scheduled base native precision keys
// are effective and actually alter rewards.
#[test]
fn base_precision_effective() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    // The initial base native precision
    const PRECISION: Precision = 1000000;
    // Write the base native precision to storage
    node.shell
        .lock()
        .unwrap()
        .state
        .write(&masp_base_native_precision_key(), PRECISION)
        .expect("unable to write base precision");
    // The scheduled base native precision
    const SCHEDULED_PRECISION: Precision = 10000;
    // Write the scheduled base native precision to storage
    node.shell
        .lock()
        .unwrap()
        .state
        .write(
            &masp_scheduled_base_native_precision_key(&MaspEpoch::new(4)),
            SCHEDULED_PRECISION,
        )
        .expect("unable to write scheduled base precision");
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Check that the stored precision is as expected
    assert_eq!(
        node.shell
            .lock()
            .unwrap()
            .state
            .read(&masp_base_native_precision_key())
            .expect("unable to read base precision"),
        Some(PRECISION),
    );
    // Send 0.1 NAM from Albert to Albert's payment address
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "0.1",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balance at Albert's viewing key is 0.1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.1"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Check that the stored precision is as expected
    assert_eq!(
        node.shell
            .lock()
            .unwrap()
            .state
            .read(&masp_base_native_precision_key())
            .expect("unable to read base precision"),
        Some(PRECISION),
    );

    // Assert NAM balance at Albert's payment address is still 0.1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    // This number would have been 0.1006 if the base precision had been 1000
    // from the beginning.
    assert!(captured.contains("nam: 0.1"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Check that the stored precision is as expected
    assert_eq!(
        node.shell
            .lock()
            .unwrap()
            .state
            .read(&masp_base_native_precision_key())
            .expect("unable to read base precision"),
        Some(PRECISION),
    );

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Check that the stored precision is as expected
    assert_eq!(
        node.shell
            .lock()
            .unwrap()
            .state
            .read(&masp_base_native_precision_key())
            .expect("unable to read base precision"),
        Some(PRECISION),
    );

    // Wait till epoch boundary. Until then, note the node is currently in the
    // 4th MASP epoch, so the scheduled base native precision will be written at
    // the end of this MASP epoch.
    node.next_masp_epoch();

    // Check that the stored precision has now changed to the scheduled
    // precision
    assert_eq!(
        node.shell
            .lock()
            .unwrap()
            .state
            .read(&masp_base_native_precision_key())
            .expect("unable to read base precision"),
        Some(SCHEDULED_PRECISION),
    );

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Check that the stored precision is as expected
    assert_eq!(
        node.shell
            .lock()
            .unwrap()
            .state
            .read(&masp_base_native_precision_key())
            .expect("unable to read base precision"),
        Some(SCHEDULED_PRECISION),
    );

    Ok(())
}

/// In this test we confirm that writing to the conversion update key is
/// effective and changes rewards from their expected trajectory.
#[test]
fn reset_conversions() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 1 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "1",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert BTC balance at VK(A) is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Assert the rewards estimate is also zero
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "estimate-shielding-rewards",
                "--key",
                AA_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(
        captured.contains(
            "Estimated native token rewards for the next MASP epoch: 0"
        )
    );

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance is a non-zero number (rewards have been dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });

    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.063"));

    // Assert the rewards estimate matches the actual rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "estimate-shielding-rewards",
                "--key",
                AA_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(
        "Estimated native token rewards for the next MASP epoch: 0.063"
    ));

    // Assert NAM balance at MASP pool is exclusively the
    // rewards from the shielded BTC
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.063"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance is a number greater than the last epoch's balance
    // (more rewards have been dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.18887"));

    // Assert the rewards estimate are 0 since we haven't shielded any more
    // tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "estimate-shielding-rewards",
                "--key",
                AA_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(
        captured.contains(
            "Estimated native token rewards for the next MASP epoch: 0"
        )
    );

    // Assert NAM balance at MASP pool is exclusively the
    // rewards from the shielded BTC
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.18887"));

    // Get the necessary information to construct BTC asset types
    let btc_alias = BTC.to_lowercase();
    let token_map_key = masp_token_map_key();
    let tokens: TokenMap = node
        .shell
        .lock()
        .unwrap()
        .state
        .read(&token_map_key)
        .unwrap()
        .unwrap_or_default();
    let btc_addr = &tokens[&btc_alias];
    let btc_denom =
        token::read_denom(&node.shell.lock().unwrap().state, btc_addr)?
            .expect("unable to read token denomination");

    // Erase the BTC rewards that have been distributed so far
    const PRECISION: i128 = 10000;
    let mut asset_types = BTreeMap::new();
    let mut precision_btcs = BTreeMap::new();
    let mut reward_deltas = BTreeMap::new();
    // BTC[ep, digit]
    let mut asset_type = |epoch, digit| {
        *asset_types.entry((epoch, digit)).or_insert_with(|| {
            encode_asset_type(btc_addr.clone(), btc_denom, digit, Some(epoch))
                .expect("unable to encode asset type")
        })
    };
    // PRECISION BTC[ep, digit]
    let mut precision_btc = |epoch, digit| {
        precision_btcs
            .entry((epoch, digit))
            .or_insert_with(|| {
                AllowedConversion::from(I128Sum::from_pair(
                    asset_type(epoch, digit),
                    PRECISION,
                ))
            })
            .clone()
    };
    // -PRECISION BTC[ep, digit] + PRECISION BTC[ep+1, digit]
    let mut reward_delta = |epoch, digit| {
        reward_deltas
            .entry((epoch, digit))
            .or_insert_with(|| {
                -precision_btc(epoch, digit)
                    + precision_btc(epoch.next().unwrap(), digit)
            })
            .clone()
    };
    let current_masp_epoch = node.current_masp_epoch();
    // Write the scheduled precision update to memory
    node.shell
        .lock()
        .unwrap()
        .state
        .write(
            &masp_scheduled_reward_precision_key(&current_masp_epoch, btc_addr),
            Precision::try_from(PRECISION).unwrap(),
        )
        .expect("unable to write scheduled precision update");
    // Write the new BTC conversions to memory
    for digit in token::MaspDigitPos::iter() {
        // -PRECISION BTC[ep, digit] + PRECISION BTC[current_ep, digit]
        let mut reward: AllowedConversion = I128Sum::zero().into();
        for epoch in MaspEpoch::iter_bounds_inclusive(
            MaspEpoch::zero(),
            current_masp_epoch.prev().unwrap(),
        )
        .rev()
        {
            // BTC[ep, digit]
            let asset_type = encode_asset_type(
                btc_addr.clone(),
                btc_denom,
                digit,
                Some(epoch),
            )
            .expect("unable to encode asset type");
            reward += reward_delta(epoch, digit);
            // Write the conversion update to memory
            node.shell
                .lock()
                .unwrap()
                .state
                .write(
                    &masp_conversion_key(&current_masp_epoch, &asset_type),
                    reward.clone(),
                )
                .expect("unable to write conversion update");
        }
    }

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance is a number greater than the last epoch's balance
    // (more rewards have been dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.17272"));

    // Assert the rewards estimate are 0 since we haven't shielded any more
    // tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "estimate-shielding-rewards",
                "--key",
                AA_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(
        "Estimated native token rewards for the next MASP epoch: 0.174772"
    ));

    // Assert NAM balance at MASP pool is exclusively the
    // rewards from the shielded BTC
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.362712"));

    Ok(())
}

/// In this test we verify that users of the MASP receive the correct rewards
/// for leaving their assets in the pool for varying periods of time.
#[test]
fn dynamic_precision() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    // Get token addresses so that their precisions can be modified
    let btc = BTC.to_lowercase();
    let token_map_key = masp_token_map_key();
    let tokens: TokenMap = node
        .shell
        .lock()
        .unwrap()
        .state
        .read(&token_map_key)
        .unwrap()
        .unwrap_or_default();
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 1 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "1",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert BTC balance at VK(A) is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Assert the rewards estimate is also zero
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "estimate-shielding-rewards",
                "--key",
                AA_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(
        captured.contains(
            "Estimated native token rewards for the next MASP epoch: 0"
        )
    );

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance is a non-zero number (rewards have been dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });

    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.063"));

    // Assert the rewards estimate matches the actual rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "estimate-shielding-rewards",
                "--key",
                AA_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(
        "Estimated native token rewards for the next MASP epoch: 0.063"
    ));

    // Assert NAM balance at MASP pool is exclusively the
    // rewards from the shielded BTC
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.063"));

    {
        node.shell
            .lock()
            .unwrap()
            .state
            .write(&masp_reward_precision_key(&tokens[&btc]), 1000000u128)
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert that existing NAM rewards have been lost
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Assert the rewards estimate are 0 since we haven't shielded any more
    // tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "estimate-shielding-rewards",
                "--key",
                AA_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(
        captured.contains(
            "Estimated native token rewards for the next MASP epoch: 0"
        )
    );

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Assert that existing NAM rewards are still lost
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Check that despite rewards being lost, unshielding the principal 1 BTC
    // amount from PA(B) to Albert works
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                AA_VIEWING_KEY,
                "--target",
                ALBERT,
                "--token",
                BTC,
                "--amount",
                "1",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert NAM balance at VK(A) is now 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 0"));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Send 1 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "1",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert BTC balance at VK(A) is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance at VK(A) is 0.253116 NAM. A reward is received because
    // the 1 BTC was shielded in the MASP epoch after the precision change.
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.25316"));

    // Check that unshielding the principal 1 BTC amount from PA(B) to Albert
    // works
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                AA_VIEWING_KEY,
                "--target",
                ALBERT,
                "--token",
                BTC,
                "--amount",
                "1",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Check that unshielding the 0.25316 NAM reward also works
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                AA_VIEWING_KEY,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "0.25316",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Unfortunately, changing the precision after non-zero rewards have already
    // been distributed leaves unclaimable NAM in the pool
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.382401"));

    Ok(())
}

/// In this test we verify that users of the MASP receive the correct rewards
/// for leaving their assets in the pool for varying periods of time.
#[test]
fn masp_incentives() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 1 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "1",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert BTC balance at VK(A) is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Assert the rewards estimate is also zero
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "estimate-shielding-rewards",
                "--key",
                AA_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(
        captured.contains(
            "Estimated native token rewards for the next MASP epoch: 0"
        )
    );

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance is a non-zero number (rewards have been dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });

    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.063"));

    // Assert the rewards estimate matches the actual rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "estimate-shielding-rewards",
                "--key",
                AA_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(
        "Estimated native token rewards for the next MASP epoch: 0.063"
    ));

    // Assert NAM balance at MASP pool is exclusively the
    // rewards from the shielded BTC
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.063"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance is a number greater than the last epoch's balance
    // (more rewards have been dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.18887"));

    // Assert the rewards estimate are 0 since we haven't shielded any more
    // tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "estimate-shielding-rewards",
                "--key",
                AA_VIEWING_KEY,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(
        captured.contains(
            "Estimated native token rewards for the next MASP epoch: 0"
        )
    );

    // Assert NAM balance at MASP pool is exclusively the
    // rewards from the shielded BTC
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.18887"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Send 0.001 ETH from Albert to PA(B)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                ETH,
                "--amount",
                "0.001",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert ETH balance at VK(B) is 0.001
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                ETH,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("eth: 0.001"));

    // Assert NAM balance at VK(B) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert ETH balance at VK(B) is still 0.001
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                ETH,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("eth: 0.001"));

    // Assert NAM balance at VK(B) is non-zero (rewards have been
    // dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.750883"));

    // Assert NAM balance at MASP pool is an accumulation of
    // rewards from both the shielded BTC and shielded ETH
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1.383286"));

    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 0.001 ETH from SK(B) to Christel
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                B_SPENDING_KEY,
                "--target",
                CHRISTEL,
                "--token",
                ETH,
                "--amount",
                "0.001",
                "--signing-keys",
                BERTHA_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert ETH balance at VK(B) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                ETH,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("eth: 0"));

    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert VK(B) retains the NAM rewards dispensed in the correct
    // amount.
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1.502496"));

    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert NAM balance at MASP pool is
    // the accumulation of rewards from the shielded assets (BTC and ETH)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 3.267817"));

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Send 1 BTC from SK(A) to Christel
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                CHRISTEL,
                "--token",
                BTC,
                "--amount",
                "1",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 0"));

    // Assert VK(A) retained the NAM rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2.268662"));

    // Assert NAM balance at MASP pool is
    // the accumulation of rewards from the shielded assets (BTC and ETH)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 3.77117"));

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert NAM balance at VK(A) is the rewards dispensed earlier
    // (since VK(A) has no shielded assets, no further rewards should
    //  be dispensed to that account)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2.268662"));

    // Assert NAM balance at VK(B) is the rewards dispensed earlier
    // (since VK(A) has no shielded assets, no further rewards should
    //  be dispensed to that account)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1.502496"));

    // Assert NAM balance at MASP pool is
    // the accumulation of rewards from the shielded assets (BTC and ETH)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 3.77117"));

    // Wait till epoch boundary to prevent conversion expiry during transaction
    // construction
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    // Send all NAM rewards from SK(B) to Christel
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                B_SPENDING_KEY,
                "--target",
                CHRISTEL,
                "--token",
                NAM,
                "--amount",
                "1.502496",
                "--gas-limit",
                "60000",
                "--signing-keys",
                BERTHA_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    // Send all NAM rewards from SK(A) to Bertha
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                "2.268662",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    // Assert NAM balance at VK(B) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Assert NAM balance at MASP pool is nearly 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.000012"));

    Ok(())
}

/// In this test we ensure that a non-converted asset type (i.e. from an older
/// epoch) can be correctly spent
///
/// 1. Shield some tokens to trigger rewards
/// 2. Shield the minimum amount 10^-6 native tokens
/// 3. Sleep for a few epochs
/// 4. Check the minimum amount is still in the shielded balance
/// 5. Spend this minimum amount succesfully
#[test]
fn spend_unconverted_asset_type() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());

    let (mut node, _services) = setup::setup()?;
    // Wait till epoch boundary
    let _ep0 = node.next_epoch();

    // 1. Shield some tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "20",
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 2. Shield the minimum amount
    node.next_epoch();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "0.000001",
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 3. Sleep for a few epochs
    for _ in 0..5 {
        node.next_epoch();
    }
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    // 4. Check the shielded balance
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.000001"));

    // 5. Spend the shielded balance
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                B_SPENDING_KEY,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "0.000001",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Attempt to spend 10 BTC at SK(A) to PA(B)
/// 3. Attempt to spend 15 BTC at SK(A) to Bertha
/// 4. Send 20 BTC from Albert to PA(A)
/// 5. Attempt to spend 10 ETH at SK(A) to PA(B)
/// 6. Spend 7 BTC at SK(A) to PA(B)
/// 7. Spend 7 BTC at SK(A) to PA(B)
/// 8. Attempt to spend 7 BTC at SK(A) to PA(B)
/// 9. Spend 6 BTC at SK(A) to PA(B)
/// 10. Assert BTC balance at VK(A) is 0
/// 11. Assert ETH balance at VK(A) is 0
/// 12. Assert balance at VK(B) is 10 BTC
/// 13. Send 10 BTC from SK(B) to Bertha
#[test]
fn masp_txs_and_queries() -> Result<()> {
    // Uncomment for better debugging
    // let _log_guard = namada_apps_lib::logging::init_from_env_or(
    //     tracing::level_filters::LevelFilter::INFO,
    // )?;
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());

    enum Response {
        Ok(&'static str),
        Err(&'static str),
    }

    let (mut node, _services) = setup::setup()?;
    _ = node.next_epoch();

    // add necessary viewing keys to shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    let txs_args = vec![
        // 0. Attempt to spend 10 BTC at SK(A) to PA(B)
        (
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "10",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
            Response::Err(""),
        ),
        // 1. Attempt to spend 15 BTC at SK(A) to Bertha
        (
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                BTC,
                "--amount",
                "15",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
            Response::Err(""),
        ),
        // 2. Send 20 BTC from Albert to PA(A)
        (
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "20",
                "--node",
                validator_one_rpc,
            ]),
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
        // 3. Attempt to spend 10 ETH at SK(A) to PA(B)
        (
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                ETH,
                "--amount",
                "10",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
            Response::Err(""),
        ),
        // 4. Spend 7 BTC at SK(A) to PA(B)
        (
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "7",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
        // 5. Spend 7 BTC at SK(A) to PA(B)
        (
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "7",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
        // 6. Attempt to spend 7 BTC at SK(A) to PA(B)
        (
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "7",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
            Response::Err(""),
        ),
        // 7. Spend 6 BTC at SK(A) to PA(B)
        (
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "6",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
        // 8. Assert BTC balance at VK(A) is 0
        (
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok("btc: 0"),
        ),
        // 9. Assert ETH balance at VK(A) is 0
        (
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                ETH,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok("eth: 0"),
        ),
        // 10. Assert balance at VK(B) is 20 BTC
        (
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
            Response::Ok("btc: 20"),
        ),
        // 11. Send 20 BTC from SK(B) to Bertha
        (
            apply_use_device(vec![
                "unshield",
                "--source",
                B_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                BTC,
                "--amount",
                "20",
                "--gas-limit",
                "60000",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
            Response::Ok(TX_APPLIED_SUCCESS),
        ),
    ];

    for (tx_args, tx_result) in &txs_args {
        // there is no need to dry run balance queries
        let dry_run_args = if tx_args[0] == "transfer"
            || tx_args[0] == "shield"
            || tx_args[0] == "unshield"
        {
            // We ensure transfers don't cross epoch boundaries.
            node.next_epoch();
            vec![true, false]
        } else {
            vec![false]
        };
        for &dry_run in &dry_run_args {
            // sync shielded context
            run(
                &node,
                Bin::Client,
                vec!["shielded-sync", "--node", validator_one_rpc],
            )?;
            let tx_args = if dry_run && is_use_device() {
                continue;
            } else if dry_run {
                [tx_args.clone(), vec!["--dry-run-wrapper"]].concat()
            } else {
                tx_args.clone()
            };
            println!(
                "{}: {:?}\n\n",
                "Running".green().underline(),
                tx_args.join(" ").yellow().underline()
            );
            let captured =
                CapturedOutput::of(|| run(&node, Bin::Client, tx_args.clone()));
            match tx_result {
                Response::Ok(TX_APPLIED_SUCCESS) => {
                    assert!(
                        captured.result.is_ok(),
                        "{:?} failed with result {:?}.\n Unread output: {}",
                        tx_args,
                        captured.result,
                        captured.output,
                    );
                    assert!(
                        captured.contains(TX_APPLIED_SUCCESS),
                        "{:?} failed to contain needle 'Transaction is \
                         valid',\nGot output '{}'",
                        tx_args,
                        captured.output
                    );
                }
                Response::Ok(out) => {
                    assert!(
                        captured.result.is_ok(),
                        "{:?} failed with result {:?}.\n Unread output: {}",
                        tx_args,
                        captured.result,
                        captured.output,
                    );
                    assert!(
                        captured.contains(out),
                        "{:?} failed to contain needle '{}',\nGot output '{}'",
                        tx_args,
                        out,
                        captured.output
                    );
                }
                Response::Err(msg) => {
                    assert!(
                        captured.result.is_err(),
                        "{:?} unexpectedly succeeded",
                        tx_args
                    );
                    assert!(
                        captured.contains(msg),
                        "{:?} failed to contain needle {},\nGot output {}",
                        tx_args,
                        msg,
                        captured.output
                    );
                }
            }
        }
    }

    Ok(())
}

/// Tests that multiple transactions can be constructed (without fetching) from
/// the shielded context and executed in the same block
#[test]
fn multiple_unfetched_txs_same_block() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_epoch();

    // Initialize accounts we can access the secret keys of
    let (cooper_alias, cooper_key) =
        make_temp_account(&node, validator_one_rpc, "Cooper", NAM, 500_000)?;

    // 1. Shield tokens
    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT_KEY,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "100",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT_KEY,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "200",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "100",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // 2. Shielded operations without fetching. Dump the txs to then reload and
    // submit in the same block
    let tempdir = tempfile::tempdir().unwrap();
    let mut txs_bytes = vec![];

    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AC_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "50",
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
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

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AC_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "50",
                "--gas-payer",
                cooper_alias,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
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

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                B_SPENDING_KEY,
                "--target",
                AC_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "50",
                "--gas-payer",
                cooper_alias,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
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

    let sk = cooper_key;
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
                amount_per_gas_unit: DenominatedAmount::native(100.into()),
                token: native_token.clone(),
            },
            pk.clone(),
            DEFAULT_GAS_LIMIT.into(),
        );
        tx.sign_wrapper(sk.clone());

        txs.push(tx.to_bytes());
    }

    node.clear_results();
    node.submit_txs(txs);
    // If empty then failed in process proposal
    assert!(!node.tx_result_codes.lock().unwrap().is_empty());
    node.assert_success();

    Ok(())
}

/// Tests that an expired masp tx is rejected by the vp. The transaction is
/// applied at the first invalid height, i.e. block_height = expiration_height +
/// 1
#[test]
fn masp_tx_expiration_first_invalid_block_height() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_epoch();

    // Initialize accounts we can access the secret keys of
    let (cooper_alias, cooper_key) =
        make_temp_account(&node, validator_one_rpc, "Cooper", NAM, 500_000)?;

    // 1. Shield tokens
    _ = node.next_epoch();
    run(
        &node,
        Bin::Client,
        apply_use_device(vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "100",
            "--ledger-address",
            validator_one_rpc,
        ]),
    )?;
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // 2. Shielded operation to avoid the need of a signature on the inner tx.
    //    Dump the tx to then reload and submit
    let tempdir = tempfile::tempdir().unwrap();

    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AC_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "50",
                "--gas-payer",
                cooper_alias,
                // We want to create an expired masp tx. Doing so will also set
                // the expiration field of the header which can
                // be a problem because this would lead to the
                // transaction being rejected by the
                // protocol check while we want to test expiration in the masp
                // vp. However, this is not a real issue: to
                // avoid the failure in protocol we are going
                // to overwrite the header with one having no
                // expiration
                "--expiration",
                #[allow(clippy::disallowed_methods)]
                &DateTimeUtc::now().to_string(),
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let tx_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();

    let sk = cooper_key;
    let pk = sk.to_public();

    let native_token = node
        .shell
        .lock()
        .unwrap()
        .state
        .in_mem()
        .native_token
        .clone();
    let mut tx = Tx::try_from_json_bytes(&tx_bytes).unwrap();
    let masp_expiry_height = tx
        .sections
        .iter()
        .find_map(|section| {
            if let Section::MaspTx(transaction) = section {
                Some(transaction)
            } else {
                None
            }
        })
        .unwrap()
        .expiry_height();
    // Remove the expiration field to avoid a failure because of it, we only
    // want to check the expiration in the masp vp
    tx.header.expiration = None;
    tx.add_wrapper(
        namada_sdk::tx::data::wrapper::Fee {
            amount_per_gas_unit: DenominatedAmount::native(100.into()),
            token: native_token.clone(),
        },
        pk.clone(),
        DEFAULT_GAS_LIMIT.into(),
    );
    tx.sign_wrapper(sk.clone());
    let wrapper_hash = tx.wrapper_hash();
    let inner_cmt = tx.first_commitments().unwrap();

    // Skip blocks to ensure expiration
    while u64::from(node.block_height()) < u64::from(masp_expiry_height) {
        node.finalize_and_commit(None);
    }
    node.clear_results();
    node.submit_txs(vec![tx.to_bytes()]);
    {
        let codes = node.tx_result_codes.lock().unwrap();
        // If empty then failed in process proposal
        assert!(!codes.is_empty());

        for code in codes.iter() {
            assert!(matches!(code, NodeResults::Ok));
        }

        let results = node.tx_results.lock().unwrap();
        // We submitted a single batch
        assert_eq!(results.len(), 1);

        for result in results.iter() {
            // The batch should contain a single inner tx
            assert_eq!(result.len(), 1);

            let inner_tx_result = result
                .get_inner_tx_result(
                    wrapper_hash.as_ref(),
                    itertools::Either::Right(inner_cmt),
                )
                .expect("Missing expected tx result")
                .as_ref()
                .expect("Result is supposed to be Ok");

            assert!(
                inner_tx_result
                    .vps_result
                    .rejected_vps
                    .contains(&namada_sdk::address::MASP)
            );
            assert!(inner_tx_result.vps_result.errors.contains(&(
                namada_sdk::address::MASP,
                "Native VP error: MASP transaction is expired".to_string()
            )));
        }
    }

    Ok(())
}

// Tests that an expired masp tx doing masp fee payment is rejected by the vp in
// process proposal. The transaction is set to be applied at the first invalid
// height, i.e. block_height = expiration_height + 1
#[test]
fn masp_tx_expiration_first_invalid_block_height_with_fee_payment() -> Result<()>
{
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_epoch();

    // Initialize account we can access the secret keys of. The account must
    // have no balance to be used as a disposable gas payer
    let (cooper_alias, cooper_key) =
        make_temp_account(&node, validator_one_rpc, "Cooper", NAM, 0)?;

    // 1. Shield tokens
    _ = node.next_epoch();
    run(
        &node,
        Bin::Client,
        apply_use_device(vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "100",
            "--ledger-address",
            validator_one_rpc,
        ]),
    )?;
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // 2. Shielded operation to avoid the need of a signature on the inner tx.
    //    Dump the tx to then reload and submit
    let tempdir = tempfile::tempdir().unwrap();

    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AC_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "50",
                // This gas payer has no funds so we are going to use it as a
                // disposable gas payer via the MASP
                "--gas-payer",
                cooper_alias,
                // We want to create an expired masp tx. Doing so will also set
                // the expiration field of the header which can
                // be a problem because this would lead to the
                // transaction being rejected by the
                // protocol check while we want to test expiration in the masp
                // vp. However, this is not a real issue: to
                // avoid the failure in protocol we are going
                // to overwrite the header with one having no
                // expiration
                "--expiration",
                #[allow(clippy::disallowed_methods)]
                &DateTimeUtc::now().to_string(),
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let tx_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();

    let sk = cooper_key;
    let pk = sk.to_public();

    let native_token = node
        .shell
        .lock()
        .unwrap()
        .state
        .in_mem()
        .native_token
        .clone();
    let mut tx = Tx::try_from_json_bytes(&tx_bytes).unwrap();
    let masp_expiry_height = tx
        .sections
        .iter()
        .find_map(|section| {
            if let Section::MaspTx(transaction) = section {
                Some(transaction)
            } else {
                None
            }
        })
        .unwrap()
        .expiry_height();
    // Remove the expiration field to avoid a failure because of it, we only
    // want to check the expiration in the masp vp
    tx.header.expiration = None;
    tx.add_wrapper(
        namada_sdk::tx::data::wrapper::Fee {
            amount_per_gas_unit: DenominatedAmount::native(100.into()),
            token: native_token.clone(),
        },
        pk.clone(),
        DEFAULT_GAS_LIMIT.into(),
    );
    tx.sign_wrapper(sk.clone());

    // Skip blocks to ensure expiration
    while u64::from(node.block_height()) < u64::from(masp_expiry_height) {
        node.finalize_and_commit(None);
    }
    node.clear_results();
    node.submit_txs(vec![tx.to_bytes()]);
    {
        // Assert that the block was rejected in process proposal
        let codes = node.tx_result_codes.lock().unwrap();
        assert!(!codes.is_empty());

        for code in codes.iter() {
            match code {
                NodeResults::Rejected(tx_result) => {
                    assert_eq!(tx_result.code, ResultCode::FeeError.to_u32());
                    assert!(
                        tx_result.info.contains("MASP transaction is expired")
                    );
                }
                _ => panic!("Test failed"),
            }
        }

        let results = node.tx_results.lock().unwrap();
        // We never made it to finalize block
        assert!(results.is_empty());
    }

    Ok(())
}

// Tests that a masp tx applied at the last valid block before expiration
// (block_height = expiration_height) is accepted by the vp
#[test]
fn masp_tx_expiration_last_valid_block_height() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_epoch();

    // Initialize accounts we can access the secret keys of
    let (cooper_alias, cooper_key) =
        make_temp_account(&node, validator_one_rpc, "Cooper", NAM, 500_000)?;

    // 1. Shield tokens
    _ = node.next_epoch();
    run(
        &node,
        Bin::Client,
        apply_use_device(vec![
            "shield",
            "--source",
            ALBERT_KEY,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--amount",
            "100",
            "--ledger-address",
            validator_one_rpc,
        ]),
    )?;
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // 2. Shielded operation to avoid the need of a signature on the inner tx.
    //    Dump the tx to then reload and submit
    let tempdir = tempfile::tempdir().unwrap();

    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AC_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "50",
                "--gas-payer",
                cooper_alias,
                // We want to create an expired masp tx. Doing so will also set
                // the expiration field of the header which can
                // be a problem because this would lead to the
                // transaction being rejected by the
                // protocol check while we want to test expiration in the masp
                // vp. However, this is not a real issue: to
                // avoid the failure in protocol we are going
                // to overwrite the header with one having no
                // expiration
                "--expiration",
                #[allow(clippy::disallowed_methods)]
                &DateTimeUtc::now().to_string(),
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let tx_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();

    let sk = cooper_key;
    let pk = sk.to_public();

    let native_token = node
        .shell
        .lock()
        .unwrap()
        .state
        .in_mem()
        .native_token
        .clone();
    let mut tx = Tx::try_from_json_bytes(&tx_bytes).unwrap();
    let masp_expiry_height = tx
        .sections
        .iter()
        .find_map(|section| {
            if let Section::MaspTx(transaction) = section {
                Some(transaction)
            } else {
                None
            }
        })
        .unwrap()
        .expiry_height();
    // Remove the expiration field to avoid a failure because of it, we only
    // want to check the expiration in the masp vp
    tx.header.expiration = None;
    tx.add_wrapper(
        namada_sdk::tx::data::wrapper::Fee {
            amount_per_gas_unit: DenominatedAmount::native(100.into()),
            token: native_token.clone(),
        },
        pk.clone(),
        DEFAULT_GAS_LIMIT.into(),
    );
    tx.sign_wrapper(sk.clone());
    let wrapper_hash = tx.wrapper_hash();
    let inner_cmt = tx.first_commitments().unwrap();

    // Skip enough blocks to get to the expiry height. Remove one from the
    // expiry height cause that will be added back in the process of producing
    // the block with the masp tx
    while u64::from(node.block_height()) < (u64::from(masp_expiry_height) - 1) {
        node.finalize_and_commit(None);
    }

    node.clear_results();
    node.submit_txs(vec![tx.to_bytes()]);
    {
        let codes = node.tx_result_codes.lock().unwrap();
        // If empty then failed in process proposal
        assert!(!codes.is_empty());

        for code in codes.iter() {
            assert!(matches!(code, NodeResults::Ok));
        }

        let results = node.tx_results.lock().unwrap();
        // We submitted a single batch
        assert_eq!(results.len(), 1);

        for result in results.iter() {
            // The batch should contain a single inner tx
            assert_eq!(result.len(), 1);

            let inner_tx_result = result
                .get_inner_tx_result(
                    wrapper_hash.as_ref(),
                    itertools::Either::Right(inner_cmt),
                )
                .expect("Missing expected tx result")
                .as_ref()
                .expect("Result is supposed to be Ok");
            assert!(inner_tx_result.is_accepted());
        }
    }

    Ok(())
}

// Test that a masp unshield transaction can be succesfully executed even across
// an epoch boundary.
#[test]
fn cross_epoch_unshield() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_epoch();

    // 1. Shield some tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1000",
                "--signing-keys",
                ALBERT_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // 2. Generate the tx in the current epoch
    let tempdir = tempfile::tempdir().unwrap();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                "100",
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());

    // Look for the only file in the temp dir
    let tx_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();

    // 3. Submit the unshielding in the following epoch
    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "tx",
                "--owner",
                ALBERT_KEY,
                "--tx-path",
                tx_path.to_str().unwrap(),
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    Ok(())
}

/// In this test we verify that users of the MASP receive the correct rewards
/// for leaving their assets in the pool for varying periods of time.
#[test]
fn dynamic_assets() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    let btc = BTC.to_lowercase();
    let nam = NAM.to_lowercase();

    let token_map_key = masp_token_map_key();
    let test_tokens = {
        // Only distribute rewards for NAM tokens
        let mut tokens: TokenMap = node
            .shell
            .lock()
            .unwrap()
            .state
            .read(&token_map_key)
            .unwrap()
            .unwrap_or_default();
        let test_tokens = tokens.clone();
        tokens.retain(|k, _v| *k == nam);
        node.shell
            .lock()
            .unwrap()
            .state
            .write(&token_map_key, tokens.clone())
            .unwrap();
        test_tokens
    };
    // add necessary viewing keys to shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 1 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "1",
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    {
        // Start decoding and distributing shielded rewards for BTC in next
        // epoch
        let mut tokens: TokenMap = node
            .shell
            .lock()
            .unwrap()
            .state
            .read(&token_map_key)
            .unwrap()
            .unwrap_or_default();
        tokens.insert(btc.clone(), test_tokens[&btc].clone());
        node.shell
            .lock()
            .unwrap()
            .state
            .write(&token_map_key, tokens)
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is still 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1"));

    // Assert NAM balance at VK(A) is still 0 since rewards were still not being
    // distributed
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Send 1 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "1",
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is now 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    // Assert NAM balance at VK(A) is still 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert that VK(A) has now received a NAM rewward for second deposit
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.063"));

    // Assert BTC balance at VK(A) is still 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    {
        // Stop distributing shielded rewards for NAM in next epoch
        let storage = &mut node.shell.lock().unwrap().state;
        storage
            .write(
                &token::storage_key::masp_max_reward_rate_key(
                    &test_tokens[&nam],
                ),
                Dec::zero(),
            )
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is still 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    // Assert that VK(A) has now received a NAM rewward for second deposit
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.189"));

    {
        // Stop decoding and distributing shielded rewards for BTC in next epoch
        let mut tokens: TokenMap = node
            .shell
            .lock()
            .unwrap()
            .state
            .read(&token_map_key)
            .unwrap()
            .unwrap_or_default();
        tokens.remove(&btc);
        node.shell
            .lock()
            .unwrap()
            .state
            .write(&token_map_key, tokens)
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is still 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    // Assert that the NAM at VK(A) is still the same
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.189"));

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    // Assert BTC balance at VK(A) is still 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    // Assert that the NAM at VK(A) is still the same
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.189"));

    {
        // Start distributing shielded rewards for NAM in next epoch
        let storage = &mut node.shell.lock().unwrap().state;
        storage
            .write(
                &token::storage_key::masp_max_reward_rate_key(
                    &test_tokens[&nam],
                ),
                Dec::from_str("0.1").unwrap(),
            )
            .unwrap();
    }

    // Wait till epoch boundary
    node.next_masp_epoch();
    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    // Assert BTC balance at VK(A) is still 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 2"));

    // Assert that the NAM at VK(A) is now increasing
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.189567"));

    // Unshield the rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                "0.189567",
                "--gas-payer",
                BERTHA_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert that the NAM at VK(A) is now null
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Unshield the principal
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                BTC,
                "--amount",
                "2",
                "--gas-payer",
                BERTHA_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert that the principal's balance is now null
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 0"));

    Ok(())
}

// Test fee payment in masp:
//
// 1. Masp fee payment runs out of gas
// 2. Attempt fee payment with a non-MASP transaction
// 3. Valid fee payment (also check that the first tx in the batch is executed
//    only once)
#[test]
fn masp_fee_payment() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();

    // Shield some tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT_KEY,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "500000",
                "--gas-payer",
                CHRISTEL_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    _ = node.next_masp_epoch();
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 500000"));

    // 1. Out of gas for masp fee payment
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-limit",
                "20000",
                "--gas-price",
                "1",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_err());
    _ = node.next_masp_epoch();
    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 500000"));

    // 2. Attempt fee payment with non-MASP transfer
    // Drain balance of Albert implicit
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                ALBERT_KEY,
                "--target",
                BERTHA_KEY,
                "--token",
                NAM,
                "--amount",
                "1500000",
                "--gas-payer",
                CHRISTEL_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                ALBERT_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Gas payer is Albert implicit, whose balance is 0. Let's try to
    // transparently send some tokens (enough to pay fees) to him and check that
    // this is not allowed
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transparent-transfer",
                "--source",
                BERTHA_KEY,
                "--target",
                ALBERT_KEY,
                "--token",
                NAM,
                "--amount",
                "200000",
                "--gas-payer",
                ALBERT_KEY,
                "--ledger-address",
                validator_one_rpc,
                // Force to skip check in client
                "--force",
            ]),
        )
    });
    assert!(captured.result.is_err());

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                ALBERT_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // 3. Valid masp fee payment
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "10000",
                "--gas-price",
                "1",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;
    // Check the exact balance of the tx source to ensure that the masp fee
    // payment transaction was executed only once
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 440000"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 10000"));

    Ok(())
}

// Test that when paying gas via masp we select the gas limit as the minimum
// between the transaction's gas limit and the protocol parameter.
#[test]
fn masp_fee_payment_gas_limit() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::initialize_genesis(|mut genesis| {
        // Set an insufficient gas limit for masp fee payment to force all
        // transactions to fail
        genesis.parameters.parameters.masp_fee_payment_gas_limit = 10_000;
        genesis
    })?;
    _ = node.next_masp_epoch();

    // Shield some tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT_KEY,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1000000",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Check that the balance hasn't changed
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1000000"));

    // Masp fee payment with huge gas, check that the tx still fails because of
    // the protocol param
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-price",
                "1",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_err());

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Check that the balance hasn't changed
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1000000"));

    Ok(())
}

// Test masp fee payment with an unshield to a non-disposable address with
// already some funds on it.
#[test]
fn masp_fee_payment_with_non_disposable() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();

    // Shield some tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT_KEY,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                // Decrease payer's balance to 1
                "1999999",
                // Pay gas transparently
                "--gas-payer",
                BERTHA_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1999999"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                ALBERT_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1"));

    // Masp fee payment to non-disposable address
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-price",
                "1",
                "--gas-limit",
                "60000",
                "--gas-payer",
                ALBERT_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1939999"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                ALBERT_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    Ok(())
}

// Test masp fee payement with a custom provided spending key. Check that fees
// are split between the actual source of the payment and this gas spending
// key
#[test]
fn masp_fee_payment_with_custom_spending_key() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();

    // Shield some tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT_KEY,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "10000",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "300000",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 10000"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 300000"));

    // Masp fee payment with custom gas payer
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AC_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "9000",
                "--gas-limit",
                "60000",
                "--gas-price",
                "1",
                "--gas-spending-key",
                B_SPENDING_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1000"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 240000"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AC_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 9000"));

    Ok(())
}

// Test masp fee payement with a different token from the one used in the
// transaction itself and with the support of a different key for gas payment
#[test]
fn masp_fee_payment_with_different_token() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::initialize_genesis(|mut genesis| {
        // Whitelist BTC for gas payment
        genesis.parameters.parameters.minimum_gas_price.insert(
            "btc".into(),
            DenominatedAmount::new(1.into(), token::Denomination(6)),
        );
        genesis
    })?;
    _ = node.next_masp_epoch();

    // Shield some tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT_KEY,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "1000",
                "--gas-payer",
                ALBERT_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "300000",
                "--gas-payer",
                ALBERT_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1000"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 300000"));

    // Masp fee payment with custom token and gas payer
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-limit",
                "60000",
                "--gas-token",
                BTC,
                "--gas-price",
                "1",
                "--gas-spending-key",
                B_SPENDING_KEY,
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    _ = node.next_masp_epoch();

    // sync shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 1000"));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 240000"));

    Ok(())
}

// An ouput description of the masp can be replayed (pushed to the commitment
// tree more than once). The nullifiers and merkle paths will be unique. Test
// that a batch containing two identical shielding txs can be executed correctly
// and the two identical notes can be spent (nullified) with no issues.
#[test]
fn identical_output_descriptions() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();
    let tempdir = tempfile::tempdir().unwrap();

    // Initialize accounts we can access the secret keys of
    let (adam_alias, adam_key) =
        make_temp_account(&node, validator_one_rpc, "Adam", NAM, 500_000)?;
    let (bradley_alias, bradley_key) =
        make_temp_account(&node, validator_one_rpc, "Bradley", NAM, 500_000)?;

    // Generate a tx to shield some tokens
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                adam_alias,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1000",
                "--gas-payer",
                bradley_alias,
                "--gas-limit",
                "60000",
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-wrapper-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let tx_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();

    // Create a batch that contains the same shielding tx twice
    let tx: namada_sdk::tx::Tx = serde_json::from_slice(&tx_bytes).unwrap();
    // Inject some randomness in the cloned tx to change the hash
    let mut tx_clone = tx.clone();
    tx_clone.add_memo(&[1, 2, 3]);

    let signing_data = SigningData::Wrapper(SigningWrapperData {
        signing_data: vec![SigningTxData {
            owner: None,
            public_keys: [adam_key.to_public()].into(),
            threshold: 1,
            account_public_keys_map: None,
            shielded_hash: None,
            signatures: vec![],
        }],

        fee_auth: FeeAuthorization::Signer {
            pubkey: adam_key.to_public(),
            disposable_fee_payer: false,
        },
    });

    let (mut batched_tx, _signing_data) = namada_sdk::tx::build_batch(vec![
        (tx, signing_data.clone()),
        (tx_clone, signing_data),
    ])
    .unwrap();

    batched_tx.sign_raw(
        vec![adam_key.clone()],
        AccountPublicKeysMap::from_iter(
            vec![(adam_key.to_public())].into_iter(),
        ),
        None,
    );
    batched_tx.sign_wrapper(bradley_key);

    let wrapper_hash = batched_tx.wrapper_hash();
    let inner_cmts = batched_tx.commitments();

    let txs = vec![batched_tx.to_bytes()];

    node.clear_results();
    node.submit_txs(txs);

    // Check that the batch was successful
    {
        let codes = node.tx_result_codes.lock().unwrap();
        // If empty then failed in process proposal
        assert!(!codes.is_empty());

        for code in codes.iter() {
            assert!(matches!(code, NodeResults::Ok));
        }

        let results = node.tx_results.lock().unwrap();
        // We submitted a single batch
        assert_eq!(results.len(), 1);

        for result in results.iter() {
            // The batch should contain two inner txs
            assert_eq!(result.len(), 2);

            for inner_cmt in inner_cmts {
                let inner_tx_result = result
                    .get_inner_tx_result(
                        wrapper_hash.as_ref(),
                        itertools::Either::Right(inner_cmt),
                    )
                    .expect("Missing expected tx result")
                    .as_ref()
                    .expect("Result is supposed to be Ok");

                assert!(inner_tx_result.is_accepted());
            }
        }
    }

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balance at VK(A) is 2000
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2000"));

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
    assert!(captured.contains("nam: 498000"));

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
    assert!(captured.contains("nam: 2000000"));

    // Spend both notes successfully
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                CHRISTEL,
                "--token",
                NAM,
                // Spend the entire shielded amount
                "--amount",
                "2000",
                "--gas-payer",
                BERTHA_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

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
    assert!(captured.contains("nam: 2002000"));

    Ok(())
}

// Extract the shielded section hash from the transaction
fn get_shielded_hash(tx: &namada_sdk::tx::Tx) -> Option<MaspTxId> {
    for section in &tx.sections {
        if let Section::MaspTx(masp) = section {
            return Some(MaspTxId::from(masp.txid()));
        }
    }
    None
}

// Test MASP batched txs where one is failing and one is successful and check
// that both the protocol and the shielded sync command behave correctly. Since
// the batches are not atomic check that the valid transactions get committed
// and the balances are correctly updated
#[test]
fn masp_batch() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();
    let tempdir = tempfile::tempdir().unwrap();

    // Initialize accounts we can access the secret keys of
    let (adam_alias, adam_key) =
        make_temp_account(&node, validator_one_rpc, "Adam", NAM, 500_000)?;
    let (bradley_alias, _bradley_key) =
        make_temp_account(&node, validator_one_rpc, "Bradley", NAM, 500_000)?;
    let (cooper_alias, cooper_key) =
        make_temp_account(&node, validator_one_rpc, "Cooper", NAM, 500_000)?;

    // Assert reference NAM balances at VK(A), Albert and Bertha
    for (owner, balance) in [
        (AA_VIEWING_KEY, 0),
        (adam_alias, 500_000),
        (bradley_alias, 500_000),
    ] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains(&format!("nam: {balance}")));
    }

    // Generate txs for the batch to shield some tokens. Use two different
    // sources
    let mut batch = vec![];
    for source in [adam_alias, bradley_alias] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "shield",
                    "--source",
                    source,
                    "--target",
                    AA_PAYMENT_ADDRESS,
                    "--token",
                    NAM,
                    "--amount",
                    "1000",
                    "--gas-limit",
                    "60000",
                    "--gas-payer",
                    cooper_alias,
                    "--output-folder-path",
                    tempdir.path().to_str().unwrap(),
                    "--dump-wrapper-tx",
                    "--ledger-address",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());

        let file_path = tempdir
            .path()
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        batch.push(std::fs::read(&file_path).unwrap());
        std::fs::remove_file(&file_path).unwrap();
    }

    // Create the batch
    let tx0: namada_sdk::tx::Tx = serde_json::from_slice(&batch[0]).unwrap();
    let tx1: namada_sdk::tx::Tx = serde_json::from_slice(&batch[1]).unwrap();

    let signing_data = SigningTxData {
        owner: None,
        public_keys: [adam_key.to_public()].into(),
        threshold: 1,
        account_public_keys_map: None,
        shielded_hash: None,
        signatures: vec![],
    };

    let mut txs = vec![];
    let mut inner_cmts = vec![];
    let mut wrapper_hashes = vec![];

    // Try different tx orders and generate a single block with both batch
    // combinations
    for (tx0, tx1) in [(tx0.clone(), tx1.clone()), (tx1, tx0)] {
        let (mut batched_tx, _signing_data) =
            namada_sdk::tx::build_batch(vec![
                (
                    tx0.clone(),
                    SigningData::Wrapper(SigningWrapperData {
                        signing_data: vec![SigningTxData {
                            shielded_hash: get_shielded_hash(&tx0),
                            ..signing_data.clone()
                        }],
                        fee_auth: FeeAuthorization::Signer {
                            pubkey: adam_key.to_public(),
                            disposable_fee_payer: false,
                        },
                    }),
                ),
                (
                    tx1.clone(),
                    SigningData::Wrapper(SigningWrapperData {
                        signing_data: vec![SigningTxData {
                            shielded_hash: get_shielded_hash(&tx1),
                            ..signing_data.clone()
                        }],
                        fee_auth: FeeAuthorization::Signer {
                            pubkey: adam_key.to_public(),
                            disposable_fee_payer: false,
                        },
                    }),
                ),
            ])
            .unwrap();
        batched_tx.header.atomic = false;

        // Sign the batch with just the signer of one tx to force the failure of
        // the other one
        batched_tx.sign_raw(
            vec![adam_key.clone()],
            AccountPublicKeysMap::from_iter(
                vec![(adam_key.to_public())].into_iter(),
            ),
            None,
        );
        batched_tx.sign_wrapper(cooper_key.clone());

        wrapper_hashes.push(batched_tx.wrapper_hash());
        for cmt in batched_tx.commitments() {
            inner_cmts.push(cmt.to_owned());
        }

        txs.push(batched_tx.to_bytes());
    }

    node.clear_results();
    node.submit_txs(txs);

    // Check the block result
    {
        let codes = node.tx_result_codes.lock().unwrap();
        // If empty then failed in process proposal
        assert!(!codes.is_empty());

        // Both batches must succeed
        for code in codes.iter() {
            assert!(matches!(code, NodeResults::Ok))
        }

        let results = node.tx_results.lock().unwrap();
        // We submitted two batches
        assert_eq!(results.len(), 2);

        // Check inner tx results of first batch
        let res0 = &results[0];
        assert_eq!(res0.len(), 2);
        let inner_tx_result = res0
            .get_inner_tx_result(
                wrapper_hashes[0].as_ref(),
                itertools::Either::Right(&inner_cmts[0]),
            )
            .expect("Missing expected tx result")
            .as_ref()
            .expect("Result is supposed to be Ok");
        assert!(inner_tx_result.is_accepted());
        let inner_tx_result = res0
            .get_inner_tx_result(
                wrapper_hashes[0].as_ref(),
                itertools::Either::Right(&inner_cmts[1]),
            )
            .expect("Missing expected tx result")
            .as_ref()
            .expect("Result is supposed to be Ok");
        assert!(!inner_tx_result.is_accepted());

        // Check inner tx results of second batch
        let res1 = &results[1];
        assert_eq!(res1.len(), 2);
        let inner_tx_result = res1
            .get_inner_tx_result(
                wrapper_hashes[1].as_ref(),
                itertools::Either::Right(&inner_cmts[2]),
            )
            .expect("Missing expected tx result")
            .as_ref()
            .expect("Result is supposed to be Ok");
        assert!(!inner_tx_result.is_accepted());
        let inner_tx_result = res1
            .get_inner_tx_result(
                wrapper_hashes[1].as_ref(),
                itertools::Either::Right(&inner_cmts[3]),
            )
            .expect("Missing expected tx result")
            .as_ref()
            .expect("Result is supposed to be Ok");
        assert!(inner_tx_result.is_accepted());
    }

    node.clear_results();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balances at VK(A), Bob and Bertha
    for (owner, balance) in [
        (AA_VIEWING_KEY, 2_000),
        (adam_alias, 498_000),
        (bradley_alias, 500_000),
    ] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains(&format!("nam: {balance}")));
    }

    Ok(())
}

// Test MASP atomic batched txs where one is failing and one is successful and
// check that both the protocol and the shielded sync command behave correctly.
// Verify that since the batch is atomic both transactions are rejected and no
// storage modifications are committed.
#[test]
fn masp_atomic_batch() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();
    let tempdir = tempfile::tempdir().unwrap();

    // Initialize accounts we can access the secret keys of
    let (adam_alias, adam_key) =
        make_temp_account(&node, validator_one_rpc, "Adam", NAM, 500_000)?;
    let (bradley_alias, _bradley_key) =
        make_temp_account(&node, validator_one_rpc, "Bradley", NAM, 500_000)?;
    let (cooper_alias, cooper_key) =
        make_temp_account(&node, validator_one_rpc, "Cooper", NAM, 500_000)?;

    // Assert reference NAM balances at VK(A), Albert and Bertha are unchanged
    for (owner, balance) in [
        (AA_VIEWING_KEY, 0),
        (adam_alias, 500_000),
        (bradley_alias, 500_000),
    ] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains(&format!("nam: {balance}")));
    }

    // Generate txs for the batch to shield some tokens. Use two different
    // sources
    let mut batch = vec![];
    for source in [adam_alias, bradley_alias] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "shield",
                    "--source",
                    source,
                    "--target",
                    AA_PAYMENT_ADDRESS,
                    "--token",
                    NAM,
                    "--amount",
                    "1000",
                    "--gas-limit",
                    "60000",
                    "--gas-payer",
                    cooper_alias,
                    "--output-folder-path",
                    tempdir.path().to_str().unwrap(),
                    "--dump-wrapper-tx",
                    "--ledger-address",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        let file_path = tempdir
            .path()
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        batch.push(std::fs::read(&file_path).unwrap());
        std::fs::remove_file(&file_path).unwrap();
    }

    // Create the batch
    let tx0: namada_sdk::tx::Tx = serde_json::from_slice(&batch[0]).unwrap();
    let tx1: namada_sdk::tx::Tx = serde_json::from_slice(&batch[1]).unwrap();

    let signing_data = SigningTxData {
        owner: None,
        public_keys: [adam_key.to_public()].into(),
        threshold: 1,
        account_public_keys_map: None,
        shielded_hash: None,
        signatures: vec![],
    };

    let mut txs = vec![];
    let mut inner_cmts = vec![];
    let mut wrapper_hashes = vec![];

    // Try different tx orders and generate a single block with both batch
    // combinations
    for (tx0, tx1) in [(tx0.clone(), tx1.clone()), (tx1, tx0)] {
        let (mut batched_tx, _signing_data) =
            namada_sdk::tx::build_batch(vec![
                (
                    tx0.clone(),
                    SigningData::Wrapper(SigningWrapperData {
                        signing_data: vec![SigningTxData {
                            shielded_hash: get_shielded_hash(&tx0),
                            ..signing_data.clone()
                        }],
                        fee_auth: FeeAuthorization::Signer {
                            pubkey: adam_key.to_public(),
                            disposable_fee_payer: false,
                        },
                    }),
                ),
                (
                    tx1.clone(),
                    SigningData::Wrapper(SigningWrapperData {
                        signing_data: vec![SigningTxData {
                            shielded_hash: get_shielded_hash(&tx1),
                            ..signing_data.clone()
                        }],
                        fee_auth: FeeAuthorization::Signer {
                            pubkey: adam_key.to_public(),
                            disposable_fee_payer: false,
                        },
                    }),
                ),
            ])
            .unwrap();
        batched_tx.header.atomic = true;

        // Sign the batch with just the signer of one tx to force the failure of
        // the other one
        batched_tx.sign_raw(
            vec![adam_key.clone()],
            AccountPublicKeysMap::from_iter(
                vec![(adam_key.to_public())].into_iter(),
            ),
            None,
        );
        batched_tx.sign_wrapper(cooper_key.clone());

        wrapper_hashes.push(batched_tx.wrapper_hash());
        for cmt in batched_tx.commitments() {
            inner_cmts.push(cmt.to_owned());
        }

        txs.push(batched_tx.to_bytes());
    }

    node.clear_results();
    node.submit_txs(txs);

    // Check the block result
    {
        let codes = node.tx_result_codes.lock().unwrap();
        // If empty then failed in process proposal
        assert_eq!(codes.len(), 2);

        // Both batches must fail
        for code in codes.iter() {
            assert!(matches!(
                code,
                NodeResults::Failed(
                    namada_node::shell::ResultCode::WasmRuntimeError
                )
            ))
        }

        let results = node.tx_results.lock().unwrap();
        // We submitted two batches
        assert_eq!(results.len(), 2);

        // Check inner tx results of first batch
        let res0 = &results[0];
        assert_eq!(res0.len(), 2);
        let inner_tx_result = res0
            .get_inner_tx_result(
                wrapper_hashes[0].as_ref(),
                itertools::Either::Right(&inner_cmts[0]),
            )
            .expect("Missing expected tx result")
            .as_ref()
            .expect("Result is supposed to be Ok");
        assert!(inner_tx_result.is_accepted());
        let inner_tx_result = res0
            .get_inner_tx_result(
                wrapper_hashes[0].as_ref(),
                itertools::Either::Right(&inner_cmts[1]),
            )
            .expect("Missing expected tx result")
            .as_ref()
            .expect("Result is supposed to be Ok");
        assert!(!inner_tx_result.is_accepted());

        // Check inner tx results of second batch, the second result is missing
        // since the atomic batch gets short-circuited
        let res1 = &results[1];
        assert_eq!(res1.len(), 1);
        let inner_tx_result = res1
            .get_inner_tx_result(
                wrapper_hashes[1].as_ref(),
                itertools::Either::Right(&inner_cmts[2]),
            )
            .expect("Missing expected tx result")
            .as_ref()
            .expect("Result is supposed to be Ok");
        assert!(!inner_tx_result.is_accepted());
    }

    node.clear_results();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balances at VK(A), Albert and Bertha are unchanged
    for (owner, balance) in [
        (AA_VIEWING_KEY, 0),
        (adam_alias, 500_000),
        (bradley_alias, 500_000),
    ] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains(&format!("nam: {balance}")));
    }

    Ok(())
}

// Test a failing atomic batch involving MASP fee payment. The MASP fee payment
// tx is applied while the second one fails. Verify that even if the batch is
// atomic, the fee paying transaction gets committed and only the second one is
// rejected.
#[test]
fn masp_failing_atomic_batch() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();
    let tempdir = tempfile::tempdir().unwrap();

    // Initialize accounts we can access the secret keys of
    let (adam_alias, adam_key) =
        make_temp_account(&node, validator_one_rpc, "Adam", NAM, 0)?;

    // Assert reference NAM balances at VK(A), Albert and Bertha are unchanged
    for owner in [AA_VIEWING_KEY, adam_alias] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains("nam: 0"));
    }

    // Shield some tokens
    for target in [AA_PAYMENT_ADDRESS, AC_PAYMENT_ADDRESS] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                apply_use_device(vec![
                    "shield",
                    "--source",
                    ALBERT,
                    "--target",
                    target,
                    "--token",
                    NAM,
                    "--amount",
                    "1000",
                    "--node",
                    validator_one_rpc,
                ]),
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains(TX_APPLIED_SUCCESS));
    }

    // Sync the shielded context and check the balance
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AC_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    for owner in [AA_VIEWING_KEY, AC_VIEWING_KEY] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains("nam: 1000"));
    }

    // Generate txs for the batch
    let mut batch = vec![];
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                adam_alias,
                "--token",
                NAM,
                "--amount",
                "1",
                // This gas limit is manually set to allow for the execution of
                // the first tx only (the second one will run out of gas
                // leading to the failure of the atomic batch)
                "--gas-limit",
                "50000",
                "--gas-price",
                "0.00001",
                "--gas-spending-key",
                A_SPENDING_KEY,
                "--gas-payer",
                adam_alias,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-wrapper-tx",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    batch.push(std::fs::read(&file_path).unwrap());
    std::fs::remove_file(&file_path).unwrap();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "transfer",
                "--source",
                C_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1",
                // Fake a transparent gas payer, fees will actually be paid by
                // the first tx of this batch
                "--gas-payer",
                CHRISTEL_KEY,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-wrapper-tx",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    batch.push(std::fs::read(&file_path).unwrap());
    std::fs::remove_file(&file_path).unwrap();

    // Create the batch
    let tx0: namada_sdk::tx::Tx = serde_json::from_slice(&batch[0]).unwrap();
    let tx1: namada_sdk::tx::Tx = serde_json::from_slice(&batch[1]).unwrap();

    let signing_data = SigningTxData {
        owner: None,
        public_keys: [adam_key.to_public()].into(),
        threshold: 1,
        account_public_keys_map: None,
        shielded_hash: None,
        signatures: vec![],
    };

    let (mut batched_tx, _signing_data) = namada_sdk::tx::build_batch(vec![
        (
            tx0.clone(),
            SigningData::Wrapper(SigningWrapperData {
                signing_data: vec![SigningTxData {
                    shielded_hash: get_shielded_hash(&tx0),
                    ..signing_data.clone()
                }],
                fee_auth: FeeAuthorization::Signer {
                    pubkey: adam_key.to_public(),
                    disposable_fee_payer: false,
                },
            }),
        ),
        (
            tx1.clone(),
            SigningData::Wrapper(SigningWrapperData {
                signing_data: vec![SigningTxData {
                    shielded_hash: get_shielded_hash(&tx1),
                    ..signing_data.clone()
                }],
                fee_auth: FeeAuthorization::Signer {
                    pubkey: adam_key.to_public(),
                    disposable_fee_payer: false,
                },
            }),
        ),
    ])
    .unwrap();
    batched_tx.header.atomic = true;

    batched_tx.sign_wrapper(adam_key.clone());
    let wrapper_hash = batched_tx.wrapper_hash();

    let mut inner_cmts = vec![];
    for cmt in batched_tx.commitments() {
        inner_cmts.push(cmt.to_owned());
    }

    node.clear_results();
    node.submit_txs(vec![batched_tx.to_bytes()]);

    // Check the block result
    {
        let codes = node.tx_result_codes.lock().unwrap();
        // If empty then failed in process proposal
        assert_eq!(codes.len(), 1);

        // Batch must fail
        assert!(matches!(
            codes[0],
            NodeResults::Failed(
                namada_node::shell::ResultCode::WasmRuntimeError
            )
        ));

        let results = node.tx_results.lock().unwrap();
        // We submitted one batch
        assert_eq!(results.len(), 1);

        // Check inner tx results
        let res0 = &results[0];
        assert_eq!(res0.len(), 2);
        let inner_tx_result = res0
            .get_inner_tx_result(
                wrapper_hash.as_ref(),
                itertools::Either::Right(&inner_cmts[0]),
            )
            .expect("Missing expected tx result")
            .as_ref()
            .expect("Result is supposed to be Ok");
        assert!(inner_tx_result.is_accepted());
        let inner_tx_result = res0
            .get_inner_tx_result(
                wrapper_hash.as_ref(),
                itertools::Either::Right(&inner_cmts[1]),
            )
            .expect("Missing expected tx result")
            .as_ref();
        assert!(inner_tx_result.is_err());
    }

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            AC_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balances at VK(A), Albert and Bertha are unchanged
    for (owner, balance) in [
        (AA_VIEWING_KEY, 998.5),
        (adam_alias, 1.0),
        (AB_VIEWING_KEY, 0.0),
        (AC_VIEWING_KEY, 1000.0),
    ] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains(&format!("nam: {balance}")));
    }

    Ok(())
}

// Test some edge-case masp txs:
//   1. A non masp tx that carries a masp section (check that both the protocol
//      and the shielded-sync command ignore this)
//   2. A masp tx that carries two masp sections (check that both the protocol
//      and the shielded-sync command only pick the correct data)
#[test]
fn tricky_masp_txs() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::initialize_genesis(|mut genesis| {
        // Set epochs per year lower to reduce the chance of an epoch change
        // before the transactions in this test are applied.
        genesis.parameters.parameters.epochs_per_year = 15_768_000;
        genesis
    })?;
    _ = node.next_masp_epoch();
    let tempdir = tempfile::tempdir().unwrap();

    // Initialize accounts we can access the secret keys of
    let (adam_alias, _adam_key) =
        make_temp_account(&node, validator_one_rpc, "Adam", NAM, 500_000)?;
    let (arthur_alias, arthur_key) =
        make_temp_account(&node, validator_one_rpc, "Arthur", NAM, 500_000)?;
    let (bradley_alias, bradley_key) =
        make_temp_account(&node, validator_one_rpc, "Bradley", NAM, 500_000)?;
    let (cooper_alias, _cooper_key) =
        make_temp_account(&node, validator_one_rpc, "Cooper", NAM, 500_000)?;

    // Assert reference NAM balances at VK(A), Albert, Bertha and Christel
    for (owner, balance) in [
        (AA_VIEWING_KEY, 0),
        (arthur_alias, 500_000),
        (bradley_alias, 500_000),
        (adam_alias, 500_000),
        (cooper_alias, 500_000),
    ] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains(&format!("nam: {balance}")));
    }

    // Generate masp tx to extract the section
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "shield",
                "--source",
                adam_alias,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1000",
                "--gas-payer",
                cooper_alias,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let masp_tx_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();
    let masp_tx: namada_sdk::tx::Tx =
        serde_json::from_slice(&masp_tx_bytes).unwrap();
    let masp_transaction = masp_tx
        .sections
        .into_iter()
        .find_map(|sec| sec.masp_tx())
        .unwrap();

    // Generate first tx
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "transparent-transfer",
                "--source",
                arthur_alias,
                "--target",
                cooper_alias,
                "--token",
                NAM,
                "--amount",
                "1000",
                "--gas-payer",
                FRANK_KEY,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-wrapper-tx",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let tx_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();

    // Attach useless masp section to tx
    let mut tx0: namada_sdk::tx::Tx =
        serde_json::from_slice(&tx_bytes).unwrap();
    tx0.add_masp_tx_section(masp_transaction.clone());

    tx0.sign_raw(
        vec![arthur_key.clone()],
        AccountPublicKeysMap::from_iter(
            vec![(arthur_key.to_public())].into_iter(),
        ),
        None,
    );
    tx0.sign_wrapper(get_unencrypted_keypair("frank-key"));

    // Generate second tx
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "shield",
                "--source",
                bradley_alias,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1000",
                "--gas-payer",
                FRANK_KEY,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-wrapper-tx",
                "--ledger-address",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let tx_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();

    // Attach another useless masp section to tx
    let mut tx1: namada_sdk::tx::Tx =
        serde_json::from_slice(&tx_bytes).unwrap();
    tx1.add_masp_tx_section(masp_transaction);

    tx1.sign_raw(
        vec![bradley_key.clone()],
        AccountPublicKeysMap::from_iter(
            vec![(bradley_key.to_public())].into_iter(),
        ),
        None,
    );
    tx1.sign_wrapper(get_unencrypted_keypair("frank-key"));

    let txs = vec![tx0.to_bytes(), tx1.to_bytes()];
    node.clear_results();
    node.submit_txs(txs);
    node.assert_success();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balances at VK(A), Albert, Bertha and Christel
    for (owner, balance) in [
        (AA_VIEWING_KEY, 1_000),
        (arthur_alias, 499_000),
        (bradley_alias, 499_000),
        (adam_alias, 500_000),
        (cooper_alias, 501_000),
    ] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains(&format!("nam: {balance}")));
    }

    Ok(())
}

// Test generation of transactions and querying balance with the speculative
// context. Also checks that the shielded history is not updated when in a
// speculative context.
#[cfg(feature = "historic-masp")]
#[test]
fn speculative_context() -> Result<()> {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    // Generate the shielded wallet in a fixed path to retrieve it later
    let mut shielded_wallet = FsShieldedUtils::new(node.genesis_dir());
    // Assert that the shielded history is empty
    assert!(shielded_wallet.history.is_empty());

    _ = node.next_masp_epoch();

    // 1. Shield some tokens in two steps two generate two different output
    //    notes
    for _ in 0..2 {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                apply_use_device(vec![
                    "shield",
                    "--source",
                    ALBERT,
                    "--target",
                    AA_PAYMENT_ADDRESS,
                    "--token",
                    NAM,
                    "--amount",
                    "100",
                    "--node",
                    validator_one_rpc,
                ]),
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains(TX_APPLIED_SUCCESS));
    }

    // 2. Sync the shielded context and check the balance
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 200"));

    let native_token = node
        .shell
        .lock()
        .unwrap()
        .state
        .in_mem()
        .native_token
        .clone();
    // Load the updated shielded wallet
    rt.block_on(shielded_wallet.load_confirmed());
    // Assert that the shielded history has been updated with the corresponding
    // entries
    assert_eq!(shielded_wallet.history.len(), 1);
    let aa_history = shielded_wallet.history.first().unwrap().1;
    assert_eq!(aa_history.len(), 2);
    let first_aa_history_entry = aa_history
        .get(&IndexedTx {
            block_height: 11.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    assert!(first_aa_history_entry.inputs.is_empty());
    let expected_outputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(100_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, first_aa_history_entry.outputs);
    let second_aa_history_entry = aa_history
        .get(&IndexedTx {
            block_height: 13.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    assert!(second_aa_history_entry.inputs.is_empty());
    let expected_outputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(100_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, second_aa_history_entry.outputs);

    // 3. Spend an amount of tokens which is less than the amount of every
    //    single note
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "90",
                "--gas-payer",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 4. Check the balance without calling shielded-sync to check the response
    //    of the speculative context
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    // The speculative context invalidates the entire note spent so we expect to
    // see the balance coming only from the second unspent note
    assert!(captured.contains("nam: 100"));
    // Load the updated shielded wallet
    rt.block_on(shielded_wallet.load_confirmed());
    // Assert that the shielded history has not been updated
    assert_eq!(shielded_wallet.history.len(), 1);
    let aa_history = shielded_wallet.history.first().unwrap().1;
    assert_eq!(aa_history.len(), 2);

    // 5. Try to spend some amount from the remaining note with a tx that will
    //    fail
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "90",
                "--gas-payer",
                ALBERT_KEY,
                // Force failure with low gas limit
                "--gas-limit",
                "10000",
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(
        "Gas error: Transaction gas exceeded the limit of 10000 gas units"
    ));

    // 6. Check that the speculative context was not updated
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 100"));
    // Load the updated shielded wallet
    rt.block_on(shielded_wallet.load_confirmed());
    // Assert that the shielded history has not been updated
    assert_eq!(shielded_wallet.history.len(), 1);
    let aa_history = shielded_wallet.history.first().unwrap().1;
    assert_eq!(aa_history.len(), 2);

    // 7. Try to spend some amount from the remaining note
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "90",
                "--gas-payer",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 8. Check the balance without calling shielded-sync to check the response
    //    of the speculative context
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    // The speculative context invalidates the entire note spent so we expect to
    // see an empty balance
    assert!(captured.contains("nam: 0"));
    // Load the updated shielded wallet
    rt.block_on(shielded_wallet.load_confirmed());
    // Assert that the shielded history has not been updated
    assert_eq!(shielded_wallet.history.len(), 1);
    let aa_history = shielded_wallet.history.first().unwrap().1;
    assert_eq!(aa_history.len(), 2);

    // 9. Finally, sync the shielded context and check the confirmed balances
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 20"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 180"));

    // Load the updated shielded wallet
    rt.block_on(shielded_wallet.load_confirmed());
    // Assert that the shielded history has been updated with the corresponding
    // entries
    assert_eq!(shielded_wallet.history.len(), 2);
    let aa_history = shielded_wallet.history.first().unwrap().1;
    assert_eq!(aa_history.len(), 4);
    let third_aa_history_entry = aa_history
        .get(&IndexedTx {
            block_height: 15.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    let expected_inputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(100_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_inputs, third_aa_history_entry.inputs);
    let expected_outputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(10_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, third_aa_history_entry.outputs);
    let fourth_aa_history_entry = aa_history
        .get(&IndexedTx {
            block_height: 19.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    let expected_inputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(100_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_inputs, fourth_aa_history_entry.inputs);
    let expected_outputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(10_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, fourth_aa_history_entry.outputs);
    let ab_history = shielded_wallet.history.get_index(1).unwrap().1;
    assert_eq!(ab_history.len(), 2);
    let first_ab_history_entry = ab_history
        .get(&IndexedTx {
            block_height: 15.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    assert!(first_ab_history_entry.inputs.is_empty());
    let expected_outputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(90_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, first_ab_history_entry.outputs);
    let second_ab_history_entry = ab_history
        .get(&IndexedTx {
            block_height: 19.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    assert!(second_ab_history_entry.inputs.is_empty());
    let expected_outputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(90_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, second_ab_history_entry.outputs);

    Ok(())
}

// Test that mixed masp tranfers and fee payments are correctly labeld by the
// protocol (by means of events) and reconstructed in the correct order by the
// client
#[test]
fn masp_events() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    _ = node.next_masp_epoch();

    // 0. Initialize accounts we can access the secret keys of
    let (adam_alias, adam_key) =
        make_temp_account(&node, validator_one_rpc, "Adam", NAM, 100_000)?;
    let adam_pk = adam_key.to_public();
    let (bradley_alias, bradley_key) =
        make_temp_account(&node, validator_one_rpc, "Bradley", NAM, 0)?;
    let (cooper_alias, cooper_key) =
        make_temp_account(&node, validator_one_rpc, "Cooper", NAM, 0)?;
    let cooper_pk = cooper_key.to_public();

    // 1. Shield some tokens in two steps two generate two different output
    //    notes
    for target in [AA_PAYMENT_ADDRESS, AC_PAYMENT_ADDRESS] {
        for _ in 0..2 {
            let captured = CapturedOutput::of(|| {
                run(
                    &node,
                    Bin::Client,
                    apply_use_device(vec![
                        "shield",
                        "--source",
                        ALBERT,
                        "--target",
                        target,
                        "--token",
                        NAM,
                        "--amount",
                        "500",
                        "--node",
                        validator_one_rpc,
                    ]),
                )
            });
            assert!(captured.result.is_ok());
            assert!(captured.contains(TX_APPLIED_SUCCESS));
        }
    }

    // 2. Sync the shielded context and check the balance
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AC_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    for owner in [AA_VIEWING_KEY, AC_VIEWING_KEY] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains("nam: 1000"));
    }

    // 3. Construct a block with three masp transactions laid out like so:
    //     1. shielding
    //     2. batch:
    //        - unshield to perform masp fee payment
    //        - masp shielded transfer
    //     3. shielded transfer (with masp fee payment)
    let tempdir = tempfile::tempdir().unwrap();
    let mut txs_bytes = vec![];
    let mut notes = BTreeMap::new();
    let tree_key = token::storage_key::masp_commitment_tree_key();
    let mut commitment_tree: CommitmentTree<Node> = node
        .shell
        .lock()
        .unwrap()
        .state
        .read(&tree_key)
        .unwrap()
        .unwrap();
    // We've produced 4 notes so far from the previous shielding operations
    assert_eq!(commitment_tree.size(), 4);

    _ = node.next_epoch();
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                adam_alias,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1000",
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-wrapper-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let bytes = std::fs::read(&file_path).unwrap();
    let tx = Tx::try_from_json_bytes(&bytes).unwrap();
    let outputs = tx
        .sections
        .iter()
        .find_map(|section| section.masp_tx())
        .unwrap()
        .sapling_bundle()
        .unwrap()
        .shielded_outputs
        .clone();
    notes.insert(2, outputs);
    txs_bytes.push(bytes);
    std::fs::remove_file(&file_path).unwrap();

    // Construct the batch
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                C_SPENDING_KEY,
                "--target",
                cooper_alias,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-limit",
                "100000",
                "--gas-price",
                "0.00001",
                "--gas-payer",
                cooper_alias,
                "--gas-spending-key",
                C_SPENDING_KEY,
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-wrapper-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let batch_tx0_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                C_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1",
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let batch_tx1_bytes = std::fs::read(&file_path).unwrap();
    std::fs::remove_file(&file_path).unwrap();

    // Create the batch
    let tx0: namada_sdk::tx::Tx =
        serde_json::from_slice(&batch_tx0_bytes).unwrap();
    let tx1: namada_sdk::tx::Tx =
        serde_json::from_slice(&batch_tx1_bytes).unwrap();
    let outputs = tx0
        .sections
        .iter()
        .find_map(|section| section.masp_tx())
        .unwrap()
        .sapling_bundle()
        .unwrap()
        .shielded_outputs
        .clone();
    notes.insert(0, outputs);
    let outputs = tx1
        .sections
        .iter()
        .find_map(|section| section.masp_tx())
        .unwrap()
        .sapling_bundle()
        .unwrap()
        .shielded_outputs
        .clone();
    notes.insert(3, outputs);

    let signing_data = SigningTxData {
        owner: None,
        // No need to sign the raw tx, only the masp section
        public_keys: Default::default(),
        threshold: 1,
        account_public_keys_map: None,
        shielded_hash: None,
        signatures: vec![],
    };

    let (batched_tx, _signing_data) = namada_sdk::tx::build_batch(vec![
        (
            tx0.clone(),
            SigningData::Wrapper(SigningWrapperData {
                signing_data: vec![SigningTxData {
                    shielded_hash: get_shielded_hash(&tx0),
                    ..signing_data.clone()
                }],
                fee_auth: FeeAuthorization::Signer {
                    pubkey: cooper_pk.clone(),
                    disposable_fee_payer: false,
                },
            }),
        ),
        (
            tx1.clone(),
            SigningData::Inner(SigningTxData {
                shielded_hash: get_shielded_hash(&tx1),
                ..signing_data.clone()
            }),
        ),
    ])
    .unwrap();
    let mut buffer = vec![];
    batched_tx.to_writer_json(&mut buffer).unwrap();
    txs_bytes.push(buffer);

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "1",
                "--gas-spending-key",
                A_SPENDING_KEY,
                "--gas-payer",
                bradley_alias,
                "--gas-limit",
                "100000",
                "--gas-price",
                "0.00001",
                "--output-folder-path",
                tempdir.path().to_str().unwrap(),
                "--dump-wrapper-tx",
                "--ledger-address",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());

    let file_path = tempdir
        .path()
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let bytes = std::fs::read(&file_path).unwrap();
    let tx = Tx::try_from_json_bytes(&bytes).unwrap();
    let outputs = tx
        .sections
        .iter()
        .find_map(|section| section.masp_tx())
        .unwrap()
        .sapling_bundle()
        .unwrap()
        .shielded_outputs
        .clone();
    notes.insert(1, outputs);
    txs_bytes.push(bytes);
    std::fs::remove_file(&file_path).unwrap();

    let mut txs = vec![];
    for (idx, bytes) in txs_bytes.iter().enumerate() {
        let mut tx = Tx::try_from_json_bytes(bytes).unwrap();
        let sk = if idx == 0 {
            tx.sign_raw(
                vec![adam_key.clone()],
                AccountPublicKeysMap::from_iter(
                    vec![(adam_pk.clone())].into_iter(),
                ),
                None,
            );
            adam_key.clone()
        } else if idx == 1 {
            cooper_key.clone()
        } else {
            bradley_key.clone()
        };
        tx.sign_wrapper(sk);
        txs.push(tx.to_bytes());
    }

    node.clear_results();
    node.submit_txs(txs);
    // If empty then failed in process proposal
    assert!(!node.tx_result_codes.lock().unwrap().is_empty());
    node.assert_success();

    // Check that the commitment tree in storage matches the expected one
    for (_, note_collection) in notes {
        for description in note_collection {
            commitment_tree
                .append(Node::from_scalar(description.cmu))
                .unwrap();
        }
    }
    let storage_commitment_tree: CommitmentTree<Node> = node
        .shell
        .lock()
        .unwrap()
        .state
        .read(&tree_key)
        .unwrap()
        .unwrap();
    assert_eq!(commitment_tree, storage_commitment_tree);

    // 4. Sync the shielded context and check the balances
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            AC_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1998"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2"));
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AC_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 997"));

    // 5. Spend all the tokens in the pool (this verifies that the client
    //    reconstructs the correct shielded state)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                A_SPENDING_KEY,
                "--target",
                bradley_alias,
                "--token",
                NAM,
                "--amount",
                "1998",
                "--gas-limit",
                "100000",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                B_SPENDING_KEY,
                "--target",
                bradley_alias,
                "--token",
                NAM,
                "--amount",
                "2",
                "--gas-limit",
                "100000",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                C_SPENDING_KEY,
                "--target",
                bradley_alias,
                "--token",
                NAM,
                "--amount",
                "997",
                "--gas-limit",
                "100000",
                "--gas-payer",
                CHRISTEL_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // 6. Check that all the shielded balances are 0
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            AC_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    for owner in [AA_VIEWING_KEY, AB_VIEWING_KEY, AC_VIEWING_KEY] {
        let captured = CapturedOutput::of(|| {
            run(
                &node,
                Bin::Client,
                vec![
                    "balance",
                    "--owner",
                    owner,
                    "--token",
                    NAM,
                    "--node",
                    validator_one_rpc,
                ],
            )
        });
        assert!(captured.result.is_ok());
        assert!(captured.contains("nam: 0"));
    }

    Ok(())
}

// Test that the builder logic is able to use, in a single transfer, both the
// asset that a note carries and the rewards that it accrued
#[test]
fn multiple_inputs_from_single_note() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::initialize_genesis(|mut genesis| {
        // Whitelist BTC for gas payment
        genesis.parameters.parameters.minimum_gas_price.insert(
            "btc".into(),
            DenominatedAmount::new(1.into(), token::Denomination(6)),
        );
        genesis
    })?;
    // Wait till epoch boundary
    node.next_masp_epoch();
    // Send 10 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "10",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert BTC balance at VK(A) is 10
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 10"));

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Skip masp epoch for rewards
    node.next_masp_epoch();

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec!["shielded-sync", "--node", validator_one_rpc],
    )?;

    // Assert BTC balance at VK(A) is still 10
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 10"));

    // Assert NAM balance is a non-zero number (rewards have been dispensed)
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });

    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.06"));

    // Assert NAM balance at MASP pool is exclusively the rewards from the
    // shielded BTC
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                MASP,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.06"));

    // Assert that only one note has been produced and can be spent
    let tree_key = token::storage_key::masp_commitment_tree_key();
    let commitment_tree: CommitmentTree<Node> = node
        .shell
        .lock()
        .unwrap()
        .state
        .read(&tree_key)
        .unwrap()
        .unwrap();
    assert_eq!(commitment_tree.size(), 1);

    // Transfer the rewards nam and use the shielded btc to pay the gas fees
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "0.06",
                "--gas-token",
                BTC,
                "--gas-limit",
                "100000",
                "--gas-price",
                "0.000001",
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok(), "{:?}", captured.result);
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Assert NAM balance at VK(B) is the entirety of the rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0.06"));

    // Assert BTC balance at VK(A) has decreased because of fees
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 9.9"));

    Ok(())
}

// Test that the shielded wallet constructs the correct history of MASP
// transactions for its keys
#[cfg(feature = "historic-masp")]
#[test]
fn history() -> Result<()> {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    // Generate the shielded wallet in a fixed path to retrieve it later
    let mut shielded_wallet = FsShieldedUtils::new(node.genesis_dir());

    // Assert that the shielded history is empty
    assert!(shielded_wallet.history.is_empty());

    // Wait till epoch boundary
    node.next_masp_epoch();

    // Send 10 NAM from Albert to PA
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "10",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Send 10 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "10",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Load the updated shielded wallet and check that the history is empty
    // since we haven't run shielded-sync yet
    rt.block_on(shielded_wallet.load_confirmed());
    assert!(shielded_wallet.history.is_empty());

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balance at VK(A) is 10
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 10"));

    // Assert BTC balance at VK(A) is 10
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 10"));

    let native_token = node
        .shell
        .lock()
        .unwrap()
        .state
        .in_mem()
        .native_token
        .clone();
    let token_map_key = masp_token_map_key();
    let tokens: TokenMap = node
        .shell
        .lock()
        .unwrap()
        .state
        .read(&token_map_key)
        .unwrap()
        .unwrap_or_default();
    let btc_addr = tokens[&BTC.to_lowercase()].clone();
    // Load the updated shielded wallet
    rt.block_on(shielded_wallet.load_confirmed());
    // Assert that the shielded history has been updated with the corresponding
    // entries
    assert_eq!(shielded_wallet.history.len(), 1);
    let aa_history = shielded_wallet.history.first().unwrap().1;
    assert_eq!(aa_history.len(), 2);
    let nam_aa_history_entry = aa_history
        .get(&IndexedTx {
            block_height: 11.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    assert!(nam_aa_history_entry.inputs.is_empty());
    let expected_outputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(10_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, nam_aa_history_entry.outputs);
    assert!(!nam_aa_history_entry.conversions);
    let btc_aa_history_entry = aa_history
        .get(&IndexedTx {
            block_height: 13.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    assert!(btc_aa_history_entry.inputs.is_empty());
    let expected_outputs: HashMap<Address, Amount> =
        [(btc_addr, Amount::from(1_000_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, btc_aa_history_entry.outputs);
    assert!(!btc_aa_history_entry.conversions);

    // Send 5 NAM from VK(A) to PB
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                AA_VIEWING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "5",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balance at VK(A) is 5
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 5"));

    // Assert BTC balance at VK(A) is 10
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 10"));

    // Assert NAM balance at VK(B) is 5
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 5"));

    // Assert BTC balance at VK(B) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 0"));

    // Load the updated shielded wallet
    rt.block_on(shielded_wallet.load_confirmed());
    // Assert that the shielded history has been updated with the corresponding
    // entries
    assert_eq!(shielded_wallet.history.len(), 2);
    let aa_history = shielded_wallet.history.first().unwrap().1;
    let ab_history = shielded_wallet.history.get_index(1).unwrap().1;
    assert_eq!(aa_history.len(), 3);
    assert_eq!(ab_history.len(), 1);
    let nam_aa_history_entry = aa_history
        .get(&IndexedTx {
            block_height: 15.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    let expected_inputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(10_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_inputs, nam_aa_history_entry.inputs);
    let expected_outputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(5_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, nam_aa_history_entry.outputs);
    assert!(!nam_aa_history_entry.conversions);
    // Check entry for VK(B)
    let nam_ab_history_entry = ab_history
        .get(&IndexedTx {
            block_height: 15.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    assert!(nam_ab_history_entry.inputs.is_empty());
    let expected_outputs: HashMap<Address, Amount> =
        [(native_token, Amount::from(5_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, nam_ab_history_entry.outputs);
    assert!(!nam_ab_history_entry.conversions);

    Ok(())
}

// Test that shielded history entries flag the presence of conversions when used
#[cfg(feature = "historic-masp")]
#[test]
fn history_with_conversions() -> Result<()> {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    // Generate the shielded wallet in a fixed path to retrieve it later
    let mut shielded_wallet = FsShieldedUtils::new(node.genesis_dir());

    // Assert that the shielded history is empty
    assert!(shielded_wallet.history.is_empty());

    // Let us now start minting NAM rewards for BTC in the shielded pool
    let token_map_key = masp_token_map_key();
    let tokens: TokenMap = node
        .shell
        .lock()
        .unwrap()
        .state
        .read(&token_map_key)
        .unwrap()
        .unwrap_or_default();
    let btc_addr = tokens[&BTC.to_lowercase()].clone();

    token::write_params(
        &Some(token::ShieldedParams {
            max_reward_rate: Dec::from_str("1.0").unwrap(),
            kp_gain_nom: Dec::from_str("9999999999").unwrap(),
            kd_gain_nom: Dec::from_str("9999999999").unwrap(),
            locked_amount_target: 999999999u64,
        }),
        &mut node.shell.lock().unwrap().state,
        &btc_addr,
        &0u8.into(),
    )?;

    // Skip a couple of masp epochs
    for _ in 0..3 {
        node.next_masp_epoch();
    }

    // Send 10 BTC from Albert to PA
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "10",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Load the updated shielded wallet and check that the history is empty
    // since we haven't run shielded-sync yet
    rt.block_on(shielded_wallet.load_confirmed());
    assert!(shielded_wallet.history.is_empty());

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert BTC balance at VK(A) is 10
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 10"));

    // Load the updated shielded wallet
    rt.block_on(shielded_wallet.load_confirmed());
    // Assert that the shielded history has been updated with the corresponding
    // entries
    assert_eq!(shielded_wallet.history.len(), 1);
    let aa_history = shielded_wallet.history.first().unwrap().1;
    assert_eq!(aa_history.len(), 1);
    let btc_aa_history_entry = aa_history
        .get(&IndexedTx {
            block_height: 27.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    assert!(btc_aa_history_entry.inputs.is_empty());
    let expected_outputs: HashMap<Address, Amount> =
        [(btc_addr.clone(), Amount::from(1_000_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, btc_aa_history_entry.outputs);
    assert!(!btc_aa_history_entry.conversions);

    // Next masp epoch to accrue rewards
    node.next_masp_epoch();

    // Assert NAM balance at VK(A) is not 0 because of rewards
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 7.5"));

    // Send 10 BTC from VK(A) to PB
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "transfer",
                "--source",
                AA_VIEWING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "10",
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert BTC balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 0"));

    // Assert NAM balance at VK(A) is not 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 7.5"));

    // Assert BTC balance at VK(B) is 10
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("btc: 10"));

    let native_token = node
        .shell
        .lock()
        .unwrap()
        .state
        .in_mem()
        .native_token
        .clone();
    // Load the updated shielded wallet
    rt.block_on(shielded_wallet.load_confirmed());
    // Assert that the shielded history has been updated with the corresponding
    // entries
    assert_eq!(shielded_wallet.history.len(), 2);
    let aa_history = shielded_wallet.history.first().unwrap().1;
    assert_eq!(aa_history.len(), 2);
    let btc_aa_history_entry = aa_history
        .get(&IndexedTx {
            block_height: 37.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    let expected_inputs: HashMap<Address, Amount> =
        [(btc_addr.clone(), Amount::from(1_000_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_inputs, btc_aa_history_entry.inputs);
    let expected_outputs: HashMap<Address, Amount> =
        [(native_token.clone(), Amount::from(7_500_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, btc_aa_history_entry.outputs);
    assert!(btc_aa_history_entry.conversions);

    let ab_history = shielded_wallet.history.get_index(1).unwrap().1;
    assert_eq!(ab_history.len(), 1);
    let btc_ab_history_entry = ab_history
        .get(&IndexedTx {
            block_height: 37.into(),
            block_index: 0.into(),
            batch_index: 0.into(),
        })
        .unwrap();
    assert!(btc_ab_history_entry.inputs.is_empty());
    let expected_outputs: HashMap<Address, Amount> =
        [(btc_addr, Amount::from(1_000_000_000))]
            .into_iter()
            .collect();
    assert_eq!(expected_outputs, btc_ab_history_entry.outputs);
    assert!(!btc_ab_history_entry.conversions);

    Ok(())
}

// Test that shielding and unshielding transactions can pay a small fee to a
// transparent address as a form of sustainability fee for frontend providers
#[test]
fn frontend_sus_fee() -> Result<()> {
    // This address doesn't matter for tests. But an argument is required.
    let validator_one_rpc = "http://127.0.0.1:26567";
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    let (mut node, _services) = setup::setup()?;
    // Wait till epoch boundary
    node.next_masp_epoch();

    // Initialize address of the frontend provider with no balance
    let (frontend_alias, _frontend_key) =
        make_temp_account(&node, validator_one_rpc, "Frontend", NAM, 0)?;

    // Test sus fee when shielding. Send 10 NAM from Albert to PA and 1 NAM to a
    // transparent address owned by the frontend provider
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "10",
                "--test-frontend-sus-fee",
                frontend_alias,
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Test sus fee when shielding. Send 10 NAM from Albert to PA and 1 NAM to a
    // shielded address owned by the frontend provider
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                NAM,
                "--amount",
                "10",
                "--test-frontend-sus-fee-shielded",
                AC_PAYMENT_ADDRESS,
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AC_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balance at VK(A) is 20
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 20"));

    // Assert NAM balance at the transparent frontend is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                frontend_alias,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1"));

    // Assert NAM balance at the shielded frontend is 1
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AC_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 1"));

    // Test sus fee when unshielding. Send 9 NAM from PA to Albert and 1 NAM to
    // a transparent address owned by the frontend provider
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                AA_VIEWING_KEY,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "9",
                "--test-frontend-sus-fee",
                frontend_alias,
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // Test sus fee when unshielding. Send 9 NAM from PA to Albert and 1 NAM to
    // a shielded address owned by the frontend provider
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            apply_use_device(vec![
                "unshield",
                "--source",
                AA_VIEWING_KEY,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "9",
                "--test-frontend-sus-fee-shielded",
                AC_PAYMENT_ADDRESS,
                "--signing-keys",
                ALBERT_KEY,
                "--node",
                validator_one_rpc,
            ]),
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains(TX_APPLIED_SUCCESS));

    // sync the shielded context
    run(
        &node,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AC_VIEWING_KEY,
            "--node",
            validator_one_rpc,
        ],
    )?;

    // Assert NAM balance at VK(A) is 0
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 0"));

    // Assert NAM balance at the transparent frontend is 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                frontend_alias,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2"));

    // Assert NAM balance at the shielded frontend is 2
    let captured = CapturedOutput::of(|| {
        run(
            &node,
            Bin::Client,
            vec![
                "balance",
                "--owner",
                AC_VIEWING_KEY,
                "--token",
                NAM,
                "--node",
                validator_one_rpc,
            ],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("nam: 2"));

    Ok(())
}
