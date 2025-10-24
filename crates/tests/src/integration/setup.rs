use std::fs;
use std::mem::ManuallyDrop;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use color_eyre::eyre::{Result, eyre};
use namada_apps_lib::cli::args;
use namada_apps_lib::client::utils::PRE_GENESIS_DIR;
use namada_apps_lib::config;
use namada_apps_lib::config::TendermintMode;
use namada_apps_lib::config::genesis::chain::Finalized;
use namada_apps_lib::config::genesis::templates;
use namada_apps_lib::config::genesis::templates::load_and_validate;
use namada_apps_lib::tendermint::Timeout;
use namada_apps_lib::tendermint_proto::google::protobuf::Timestamp;
use namada_apps_lib::wallet::defaults::derive_template_dir;
use namada_apps_lib::wallet::pre_genesis;
use namada_core::chain::ChainIdPrefix;
use namada_core::collections::HashMap;
use namada_node::shell::Shell;
use namada_node::shell::testing::node::{
    InnerMockNode, MockNode, MockServicesCfg, MockServicesController,
    MockServicesPackage, SalvageableTestDir, mock_services,
};
use namada_node::shell::testing::utils::TestDir;
use namada_sdk::dec::Dec;
use namada_sdk::token;
use namada_sdk::wallet::alias::Alias;

use crate::e2e::setup::copy_wasm_to_chain_dir;

/// Env. var for keeping temporary files created by the integration tests
const ENV_VAR_KEEP_TEMP: &str = "NAMADA_INT_KEEP_TEMP";

/// Setup a network with a single genesis validator node.
pub fn setup() -> Result<(MockNode, MockServicesController)> {
    initialize_genesis(|genesis| genesis)
}

/// Setup folders with genesis, configs, wasm, etc.
pub fn initialize_genesis(
    update_genesis: impl FnMut(
        templates::All<templates::Unvalidated>,
    ) -> templates::All<templates::Unvalidated>,
) -> Result<(MockNode, MockServicesController)> {
    initialize_genesis_aux(update_genesis, None)
}

/// Setup folders with genesis, configs, wasm, etc. Allows to override
/// `keep_temp` irrespective of the `ENV_VAR_KEEP_TEMP` env var.
pub fn initialize_genesis_aux(
    mut update_genesis: impl FnMut(
        templates::All<templates::Unvalidated>,
    ) -> templates::All<templates::Unvalidated>,
    keep_temp: Option<bool>,
) -> Result<(MockNode, MockServicesController)> {
    let working_dir = std::fs::canonicalize("../..").unwrap();
    let keep_temp =
        keep_temp.unwrap_or_else(|| match std::env::var(ENV_VAR_KEEP_TEMP) {
            Ok(val) => !val.eq_ignore_ascii_case("false"),
            _ => false,
        });
    let test_dir = TestDir::new();
    let template_dir = derive_template_dir(&working_dir);

    // Copy genesis files to test directory.
    let mut templates = templates::All::read_toml_files(&template_dir)
        .expect("Missing genesis files");
    for (_, config) in templates.tokens.token.iter_mut() {
        config.masp_params = Some(token::ShieldedParams {
            max_reward_rate: Dec::from_str("0.1").unwrap(),
            kp_gain_nom: Dec::from_str("0.1").unwrap(),
            kd_gain_nom: Dec::from_str("0.1").unwrap(),
            locked_amount_target: 1_000_000u64,
        });
    }
    let templates = update_genesis(templates);
    let genesis_path = test_dir.path().join("int-test-genesis-src");
    std::fs::create_dir(&genesis_path)
        .expect("Could not create test chain directory.");
    templates
        .write_toml_files(&genesis_path)
        .expect("Could not write genesis files into test chain directory.");

    // Finalize the genesis config to derive the chain ID
    let templates = load_and_validate(&genesis_path)
        .expect("Missing or invalid genesis files");
    let genesis_time = Default::default();
    let chain_id_prefix = ChainIdPrefix::from_str("integration-test").unwrap();
    let genesis = config::genesis::chain::finalize(
        templates,
        chain_id_prefix.clone(),
        genesis_time,
        Timeout::from_str("30s").unwrap(),
    );
    let chain_id = &genesis.metadata.chain_id;

    // Run `init-network` to generate the finalized genesis config, keys and
    // addresses and update WASM checksums
    let wasm_checksums_path = working_dir.join("wasm/checksums.json");
    let global_args = args::Global {
        is_pre_genesis: true,
        chain_id: Some(chain_id.clone()),
        base_dir: test_dir.path().to_path_buf(),
        wasm_dir: Some(test_dir.path().join(chain_id.as_str()).join("wasm")),
    };

    // Create genesis chain release archive
    let release_archive_path = namada_apps_lib::client::utils::init_network(
        global_args.clone(),
        args::InitNetwork {
            templates_path: genesis_path,
            wasm_checksums_path,
            chain_id_prefix,
            consensus_timeout_commit: Timeout::from_str("30s").unwrap(),
            archive_dir: Some(test_dir.path().to_path_buf()),
            genesis_time,
        },
    );

    // Decode and unpack the release archive
    let mut archive = {
        let decoder = flate2::read::GzDecoder::new(
            fs::File::open(&release_archive_path).unwrap(),
        );
        tar::Archive::new(decoder)
    };
    archive.unpack(&global_args.base_dir).unwrap();
    _ = archive;

    // Remove release archive
    fs::remove_file(release_archive_path).unwrap();

    let eth_bridge_params = genesis.get_eth_bridge_params();
    let auto_drive_services = {
        // NB: for now, the only condition that
        // dictates whether mock services should
        // be enabled is if the Ethereum bridge
        // is enabled at genesis
        eth_bridge_params.is_some()
    };
    let enable_eth_oracle = {
        // NB: we only enable the oracle if the
        // Ethereum bridge is enabled at genesis
        eth_bridge_params.is_some()
    };
    let services_cfg = MockServicesCfg {
        auto_drive_services,
        enable_eth_oracle,
    };
    finalize_wallet(&template_dir, &global_args, genesis);
    create_node(test_dir, global_args, keep_temp, services_cfg)
}

/// Add the address from the finalized genesis to the wallet.
/// Additionally add the validator keys to the wallet.
fn finalize_wallet(
    template_dir: &Path,
    global_args: &args::Global,
    genesis: Finalized,
) {
    let pre_genesis_path = template_dir.join("src").join(PRE_GENESIS_DIR);
    let validator_alias_and_dir =
        Some(("validator-0", pre_genesis_path.join("validator-0")));
    // Pre-load the validator pre-genesis wallet and its keys to validate that
    // everything is in place
    let validator_alias_and_pre_genesis_wallet =
        validator_alias_and_dir.map(|(validator_alias, pre_genesis_dir)| {
            (
                Alias::from(validator_alias),
                pre_genesis::load(&pre_genesis_dir).unwrap_or_else(|err| {
                    panic!("Error loading validator pre-genesis wallet {err}")
                }),
            )
        });

    // Load pre-genesis wallet
    let pre_genesis_wallet =
        namada_apps_lib::wallet::load(&pre_genesis_path).unwrap();
    let chain_dir = global_args
        .base_dir
        .join(global_args.chain_id.as_ref().unwrap().as_str());
    // Derive wallet from genesis
    let wallet = genesis.derive_wallet(
        &chain_dir,
        Some(pre_genesis_wallet),
        validator_alias_and_pre_genesis_wallet,
    );
    namada_apps_lib::wallet::save(&wallet).unwrap();
}

/// Create a mock ledger node.
fn create_node(
    test_dir: TestDir,
    global_args: args::Global,
    keep_temp: bool,
    services_cfg: MockServicesCfg,
) -> Result<(MockNode, MockServicesController)> {
    // look up the chain id from the global file.
    let chain_id = global_args.chain_id.unwrap_or_default();

    // copy compiled wasms into the wasm directory
    copy_wasm_to_chain_dir(
        &std::fs::canonicalize("../..").unwrap(),
        &global_args.base_dir,
        &chain_id,
    );

    // instantiate and initialize the ledger node.
    let MockServicesPackage {
        auto_drive_services,
        services,
        shell_handlers,
        controller,
    } = mock_services(services_cfg);
    let node = MockNode(Arc::new(InnerMockNode {
        shell: Mutex::new(Shell::new(
            config::Ledger::new(
                global_args.base_dir,
                chain_id.clone(),
                TendermintMode::Validator,
            ),
            global_args
                .wasm_dir
                .expect("Wasm path not provided to integration test setup."),
            shell_handlers.tx_broadcaster,
            shell_handlers.eth_oracle_channels,
            None,
            None,
            50 * 1024 * 1024, // 50 kiB
            50 * 1024 * 1024, // 50 kiB
        )),
        test_dir: SalvageableTestDir {
            keep_temp,
            test_dir: ManuallyDrop::new(test_dir),
        },
        services,
        tx_result_codes: Mutex::new(vec![]),
        tx_results: Mutex::new(vec![]),
        blocks: Mutex::new(HashMap::new()),
        auto_drive_services,
    }));
    let init_req =
        namada_apps_lib::tendermint::abci::request::InitChain {
            time: Timestamp {
                seconds: 0,
                nanos: 0,
            }
            .try_into().unwrap(),
            chain_id: chain_id.to_string(),
            consensus_params:
                namada_apps_lib::tendermint::consensus::params::Params {
                    block: namada_apps_lib::tendermint::block::Size {
                        max_bytes: 0,
                        max_gas: 0,
                        time_iota_ms: 0,
                    },
                    evidence:
                     namada_apps_lib::tendermint::evidence::Params {
                        max_age_num_blocks:  0,
                        max_age_duration: namada_apps_lib::tendermint::evidence::Duration(core::time::Duration::MAX),
                        max_bytes: 0,
                    },
                    validator: namada_apps_lib::tendermint::consensus::params::ValidatorParams {
                        pub_key_types: vec![]
                    },
                    version: None,
                    abci: namada_apps_lib::tendermint::consensus::params::AbciParams {
                        vote_extensions_enable_height: None,
                    },
                },
            validators: vec![],
            app_state_bytes: vec![].into(),
            initial_height: 0_u32.into(),
        };
    {
        let mut locked = node.shell.lock().unwrap();
        locked
            .init_chain(init_req, 1)
            .map_err(|e| eyre!("Failed to initialize ledger: {:?}", e))?;
        // set the height of the first block (should be 1)
        locked.state.in_mem_mut().block.height = 1.into();
        locked.commit();
    }

    Ok((node, controller))
}
