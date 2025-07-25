#[cfg(test)]
mod test_bridge_pool_vp {
    use std::cell::RefCell;
    use std::path::PathBuf;

    use borsh::BorshDeserialize;
    use namada_apps_lib::wallet::defaults::{albert_address, bertha_address};
    use namada_apps_lib::wasm_loader;
    use namada_sdk::address::testing::{nam, wnam};
    use namada_sdk::borsh::BorshSerializeExt;
    use namada_sdk::chain::ChainId;
    use namada_sdk::eth_bridge::storage::bridge_pool::BRIDGE_POOL_ADDRESS;
    use namada_sdk::eth_bridge::{
        Contracts, Erc20WhitelistEntry, EthereumBridgeParams,
        UpgradeableContract, wrapped_erc20s,
    };
    use namada_sdk::eth_bridge_pool::{
        GasFee, PendingTransfer, TransferToEthereum, TransferToEthereumKind,
    };
    use namada_sdk::ethereum_events::EthAddress;
    use namada_sdk::gas::VpGasMeter;
    use namada_sdk::key::{SecretKey, common, ed25519};
    use namada_sdk::token::Amount;
    use namada_sdk::tx::{TX_BRIDGE_POOL_WASM as ADD_TRANSFER_WASM, Tx};
    use namada_sdk::validation::EthBridgePoolVp;
    use namada_tx_prelude::BatchedTx;

    use crate::native_vp::TestNativeVpEnv;
    use crate::tx::{TestTxEnv, tx_host_env};
    const ASSET: EthAddress = EthAddress([1; 20]);
    const BERTHA_WEALTH: u64 = 1_000_000;
    const BERTHA_TOKENS: u64 = 10_000;
    const GAS_FEE: u64 = 100;
    const TOKENS: u64 = 10;
    const TOKEN_CAP: u64 = TOKENS;

    /// A signing keypair for good old Bertha.
    fn bertha_keypair() -> common::SecretKey {
        // generated from
        // [`namada_sdk::key::ed25519::gen_keypair`]
        let bytes = [
            240, 3, 224, 69, 201, 148, 60, 53, 112, 79, 80, 107, 101, 127, 186,
            6, 176, 162, 113, 224, 62, 8, 183, 187, 124, 234, 244, 251, 92, 36,
            119, 243,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    /// Gets the absolute path to wasm directory
    fn wasm_dir() -> PathBuf {
        let mut current_path = std::env::current_dir()
            .expect("Current directory should exist")
            .canonicalize()
            .expect("Current directory should exist");
        while current_path.file_name().unwrap() != "tests" {
            current_path.pop();
        }
        // Two-dirs up to root
        current_path.pop();
        current_path.pop();
        current_path.join("wasm")
    }

    /// Create necessary accounts and balances for the test.
    fn setup_env(batched_tx: BatchedTx) -> TestTxEnv {
        let mut env = TestTxEnv {
            batched_tx,
            ..Default::default()
        };
        let config = EthereumBridgeParams {
            erc20_whitelist: vec![Erc20WhitelistEntry {
                token_address: wnam(),
                token_cap: Amount::from_u64(TOKEN_CAP).native_denominated(),
            }],
            eth_start_height: Default::default(),
            min_confirmations: Default::default(),
            contracts: Contracts {
                native_erc20: wnam(),
                bridge: UpgradeableContract {
                    address: EthAddress([42; 20]),
                    version: Default::default(),
                },
            },
        };
        // initialize Ethereum bridge storage
        config.init_storage(&mut env.state);
        // initialize Bertha's account
        env.spawn_accounts([&albert_address(), &bertha_address(), &nam()]);
        // enrich Albert
        env.credit_tokens(&albert_address(), &nam(), BERTHA_WEALTH.into());
        // enrich Bertha
        env.credit_tokens(&bertha_address(), &nam(), BERTHA_WEALTH.into());
        // Bertha has ERC20 tokens too.
        let token = wrapped_erc20s::token(&ASSET);
        env.credit_tokens(&bertha_address(), &token, BERTHA_TOKENS.into());
        // Bertha has... NUTs? :D
        let nuts = wrapped_erc20s::nut(&ASSET);
        env.credit_tokens(&bertha_address(), &nuts, BERTHA_TOKENS.into());
        // give Bertha some wNAM. technically this is impossible to mint,
        // but we're testing invalid protocol paths...
        let wnam_tok_addr = wrapped_erc20s::token(&wnam());
        env.credit_tokens(
            &bertha_address(),
            &wnam_tok_addr,
            BERTHA_TOKENS.into(),
        );
        env
    }

    fn run_vp(tx: BatchedTx) -> bool {
        let env = setup_env(tx);
        tx_host_env::set(env);
        let mut tx_env = tx_host_env::take();
        tx_env.execute_tx().expect("Test failed.");
        let gas_meter = RefCell::new(VpGasMeter::new_from_meter(
            &*tx_env.gas_meter.borrow(),
        ));
        let vp_env = TestNativeVpEnv::from_tx_env(tx_env, BRIDGE_POOL_ADDRESS);

        let ctx = vp_env.ctx(&gas_meter);
        EthBridgePoolVp::validate_tx(
            &ctx,
            &vp_env.tx_env.batched_tx.to_ref(),
            &vp_env.keys_changed,
            &vp_env.verifiers,
        )
        .is_ok()
    }

    fn validate_tx(tx: BatchedTx) {
        #[cfg(feature = "namada-eth-bridge")]
        {
            assert!(run_vp(tx));
        }
        #[cfg(not(feature = "namada-eth-bridge"))]
        {
            // NB: small hack to always check we reject txs
            // if the bridge is disabled at compile time
            invalidate_tx(tx)
        }
    }

    fn invalidate_tx(tx: BatchedTx) {
        assert!(!run_vp(tx));
    }

    fn create_tx(
        transfer: PendingTransfer,
        keypair: &common::SecretKey,
    ) -> BatchedTx {
        let data = transfer.serialize_to_vec();
        let wasm_code =
            wasm_loader::read_wasm_or_exit(wasm_dir(), ADD_TRANSFER_WASM);

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(wasm_code, None)
            .add_serialized_data(data)
            .sign_wrapper(keypair.clone());
        tx.batch_first_tx()
    }

    #[test]
    fn validate_erc20_tx() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: ASSET,
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKENS),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: Amount::from(GAS_FEE),
                payer: bertha_address(),
            },
        };
        validate_tx(create_tx(transfer, &bertha_keypair()));
    }

    #[test]
    fn validate_mint_wnam_tx() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKENS),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: Amount::from(GAS_FEE),
                payer: bertha_address(),
            },
        };
        validate_tx(create_tx(transfer, &bertha_keypair()));
    }

    #[test]
    fn invalidate_wnam_over_cap_tx() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKEN_CAP + 1),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: Amount::from(GAS_FEE),
                payer: bertha_address(),
            },
        };
        invalidate_tx(create_tx(transfer, &bertha_keypair()));
    }

    #[test]
    fn validate_mint_wnam_different_sender_tx() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKENS),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: Amount::from(GAS_FEE),
                payer: albert_address(),
            },
        };
        validate_tx(create_tx(transfer, &bertha_keypair()));
    }

    #[test]
    fn invalidate_fees_paid_in_nuts() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKENS),
            },
            gas_fee: GasFee {
                token: wrapped_erc20s::nut(&ASSET),
                amount: Amount::from(GAS_FEE),
                payer: bertha_address(),
            },
        };
        invalidate_tx(create_tx(transfer, &bertha_keypair()));
    }

    #[test]
    fn invalidate_fees_paid_in_wnam() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKENS),
            },
            gas_fee: GasFee {
                token: wrapped_erc20s::token(&wnam()),
                amount: Amount::from(GAS_FEE),
                payer: bertha_address(),
            },
        };
        invalidate_tx(create_tx(transfer, &bertha_keypair()));
    }

    #[test]
    fn validate_erc20_tx_with_same_gas_token() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: ASSET,
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKENS),
            },
            gas_fee: GasFee {
                token: wrapped_erc20s::token(&ASSET),
                amount: Amount::from(GAS_FEE),
                payer: bertha_address(),
            },
        };
        validate_tx(create_tx(transfer, &bertha_keypair()));
    }

    #[test]
    fn validate_wnam_tx_with_diff_gas_token() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: Amount::from(TOKENS),
            },
            gas_fee: GasFee {
                token: wrapped_erc20s::token(&ASSET),
                amount: Amount::from(GAS_FEE),
                payer: bertha_address(),
            },
        };
        validate_tx(create_tx(transfer, &bertha_keypair()));
    }
}
