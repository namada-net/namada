use std::fs::File;
use std::io::Write;

use color_eyre::owo_colors::OwoColorize;
use ledger_namada_rs::{BIP44Path, KeyResponse, NamadaApp, NamadaKeys};
use masp_primitives::sapling::redjubjub::PrivateKey;
use masp_primitives::sapling::{ProofGenerationKey, redjubjub};
use masp_primitives::transaction::components::sapling;
use masp_primitives::transaction::components::sapling::builder::{
    BuildParams, ConvertBuildParams, OutputBuildParams, RngBuildParams,
    SpendBuildParams, StoredBuildParams,
};
use masp_primitives::transaction::components::sapling::fees::InputView;
use masp_primitives::zip32::{
    ExtendedFullViewingKey, ExtendedKey, PseudoExtendedKey,
};
use namada_core::masp::MaspTransaction;
use namada_sdk::address::{Address, ImplicitAddress, MASP};
use namada_sdk::args::TxBecomeValidator;
use namada_sdk::borsh::{BorshDeserialize, BorshSerializeExt};
use namada_sdk::collections::HashMap;
use namada_sdk::governance::cli::onchain::{
    DefaultProposal, PgfFundingProposal, PgfStewardProposal,
};
use namada_sdk::ibc::convert_masp_tx_to_ibc_memo;
use namada_sdk::io::{Io, display_line, edisplay_line};
use namada_sdk::key::*;
use namada_sdk::rpc::{InnerTxResult, TxBroadcastData, TxResponse};
use namada_sdk::signing::SigningData;
use namada_sdk::state::EPOCH_SWITCH_BLOCKS_DELAY;
use namada_sdk::tx::data::compute_inner_tx_hash;
use namada_sdk::tx::{CompressedAuthorization, Section, Signer, Tx};
use namada_sdk::wallet::alias::{validator_address, validator_consensus_key};
use namada_sdk::wallet::{Wallet, WalletIo};
use namada_sdk::{ExtendedViewingKey, Namada, error, signing, tx};
use rand::rngs::OsRng;
use tokio::sync::RwLock;

use super::rpc;
use crate::cli::{args, safe_exit};
use crate::client::tx::signing::{SigningTxData, default_sign};
use crate::client::tx::tx::ProcessTxResponse;
use crate::config::TendermintMode;
use crate::tendermint_node;
use crate::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::wallet::{
    WalletTransport, gen_validator_keys, read_and_confirm_encryption_password,
};

// Maximum number of spend description randomness parameters that can be
// generated on the hardware wallet. It is hard to compute the exact required
// number because a given MASP source could be distributed amongst several
// notes.
const MAX_HW_SPEND: usize = 15;
// Maximum number of convert description randomness parameters that can be
// generated on the hardware wallet. It is hard to compute the exact required
// number because the number of conversions that are used depends on the
// protocol's current state.
const MAX_HW_CONVERT: usize = 15;
// Maximum number of output description randomness parameters that can be
// generated on the hardware wallet. It is hard to compute the exact required
// number because the number of outputs depends on the number of dummy outputs
// introduced.
const MAX_HW_OUTPUT: usize = 15;

// FIXME: remove if unused, or review the docs
// /// Wrapper around `signing::aux_signing_data` that stores the optional
// /// disposable address to the wallet
// pub async fn aux_signing_data(
//     context: &impl Namada,
//     args: &args::Tx,
//     owner: Option<Address>,
//     default_signer: Option<Address>,
//     disposable_signing_key: bool,
//     signatures: Vec<Vec<u8>>,
//     wrapper_signature: Option<Vec<u8>>,
// ) -> Result<signing::SigningTxData, error::Error> {
//     let signing_data = signing::aux_signing_data(
//         context,
//         args,
//         owner,
//         default_signer,
//         vec![],
//         disposable_signing_key,
//         signatures,
//         wrapper_signature,
//     )
//     .await?;

//     Ok(signing_data)
// }

pub async fn with_hardware_wallet<U, T>(
    mut tx: Tx,
    pubkey: common::PublicKey,
    parts: signing::Signable,
    (wallet, app): (&RwLock<Wallet<U>>, &NamadaApp<T>),
) -> Result<Tx, error::Error>
where
    U: WalletIo + Clone,
    T: ledger_transport::Exchange + Send + Sync,
    <T as ledger_transport::Exchange>::Error: std::error::Error,
{
    // Obtain derivation path
    let path = wallet
        .read()
        .await
        .find_path_by_pkh(&(&pubkey).into())
        .map_err(|_| {
            error::Error::Other(
                "Unable to find derivation path for key".to_string(),
            )
        })?;
    let path = BIP44Path {
        path: path.to_string(),
    };
    // Now check that the public key at this path in the Ledger
    // matches
    let response_pubkey = app
        .get_address_and_pubkey(&path, false)
        .await
        .map_err(|err| error::Error::Other(err.to_string()))?;
    let response_pubkey =
        common::PublicKey::try_from_slice(&response_pubkey.public_key)
            .map_err(|err| {
                error::Error::Other(format!(
                    "unable to decode public key from hardware wallet: {}",
                    err
                ))
            })?;
    if response_pubkey != pubkey {
        return Err(error::Error::Other(format!(
            "Unrecognized public key fetched from Ledger: {}. Expected {}.",
            response_pubkey, pubkey,
        )));
    }
    // Get the Ledger to sign using our obtained derivation path
    println!(
        "Requesting that hardware wallet sign transaction with transparent \
         key at {}...",
        path.path
    );
    let response = app
        .sign(&path, &tx.serialize_to_vec())
        .await
        .map_err(|err| error::Error::Other(err.to_string()))?;
    // Sign the raw header if that is requested
    if parts == signing::Signable::RawHeader
        || parts == signing::Signable::FeeRawHeader
    {
        let pubkey = common::PublicKey::try_from_slice(&response.pubkey)
            .expect("unable to parse public key from Ledger");
        let signature =
            common::Signature::try_from_slice(&response.raw_signature)
                .expect("unable to parse signature from Ledger");
        // Signatures from the Ledger come back in compressed
        // form
        let compressed = CompressedAuthorization {
            targets: response.raw_indices,
            signer: Signer::PubKeys(vec![pubkey]),
            signatures: [(0, signature)].into(),
        };
        // Expand out the signature before adding it to the
        // transaction
        tx.add_section(Section::Authorization(compressed.expand(&tx)));
    }
    // Sign the fee header if that is requested
    if parts == signing::Signable::FeeRawHeader {
        let pubkey = common::PublicKey::try_from_slice(&response.pubkey)
            .expect("unable to parse public key from Ledger");
        let signature =
            common::Signature::try_from_slice(&response.wrapper_signature)
                .expect("unable to parse signature from Ledger");
        // Signatures from the Ledger come back in compressed
        // form
        let compressed = CompressedAuthorization {
            targets: response.wrapper_indices,
            signer: Signer::PubKeys(vec![pubkey]),
            signatures: [(0, signature)].into(),
        };
        // Expand out the signature before adding it to the
        // transaction
        tx.add_section(Section::Authorization(compressed.expand(&tx)));
    }
    Ok(tx)
}

// Sign the given transaction using a hardware wallet as a backup
pub async fn sign<N: Namada>(
    context: &N,
    tx: &mut Tx,
    args: &args::Tx,
    signing_data: SigningData,
) -> Result<(), error::Error> {
    // Setup a reusable context for signing transactions using the Ledger
    if args.use_device {
        let transport = WalletTransport::from_arg(args.device_transport);
        let app = NamadaApp::new(transport);
        let with_hw_data = (context.wallet_lock(), &app);
        // Finally, begin the signing with the Ledger as backup
        context
            .sign(
                tx,
                args,
                signing_data,
                with_hardware_wallet::<N::WalletUtils, _>,
                with_hw_data,
            )
            .await?;
    } else {
        // Otherwise sign without a backup procedure
        context
            .sign(tx, args, signing_data, default_sign, ())
            .await?;
    }
    Ok(())
}

// Build a transaction to reveal the signer of the given transaction.
pub async fn submit_reveal_aux(
    context: &impl Namada,
    args: &args::Tx,
    address: &Address,
) -> Result<Option<(Tx, SigningData)>, error::Error> {
    if args.dump_tx || args.dump_wrapper_tx {
        return Ok(None);
    }

    if let Address::Implicit(ImplicitAddress(pkh)) = address {
        let public_key = context
            .wallet_mut()
            .await
            .find_public_key_by_pkh(pkh)
            .map_err(|e| error::Error::Other(e.to_string()))?;

        if tx::is_reveal_pk_needed(context.client(), address).await? {
            display_line!(
                context.io(),
                "Submitting a tx to reveal the public key for address \
                 {address}"
            );
            return Ok(Some(
                tx::build_reveal_pk(context, args, &public_key).await?,
            ));
        }
    }

    Ok(None)
}

async fn batch_opt_reveal_pk_and_submit<N: Namada>(
    namada: &N,
    args: &args::Tx,
    owners: &[&Address],
    mut tx_data: (Tx, SigningData),
) -> Result<ProcessTxResponse, error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    if !matches!(tx_data.1, SigningData::Wrapper(_)) {
        panic!("Expected wrapper signing data to submit the transaction");
    }

    let mut batched_tx_data = vec![];

    for owner in owners {
        if let Some(reveal_pk_tx_data) =
            submit_reveal_aux(namada, args, owner).await?
        {
            batched_tx_data.push(reveal_pk_tx_data);
        }
    }

    // Since hardware wallets do not yet support batched transactions, use a
    // different logic in order to achieve compatibility
    if args.use_device {
        // Sign each transaction separately
        for (tx, sig_data) in &mut batched_tx_data {
            sign(namada, tx, args, sig_data.to_owned()).await?;
        }
        sign(namada, &mut tx_data.0, args, tx_data.1).await?;
        // Then submit each transaction separately
        for (tx, _sig_data) in batched_tx_data {
            namada.submit(tx, args).await?;
        }
        // The result of submitting this function's argument is what is returned
        namada.submit(tx_data.0, args).await
    } else {
        // Otherwise complete the batch with this function's argument
        batched_tx_data.push(tx_data);
        let (mut batched_tx, batched_signing_data) =
            namada_sdk::tx::build_batch(batched_tx_data)?;
        // Sign the batch with the union of the signers required for each part
        for sig_data in batched_signing_data {
            sign(namada, &mut batched_tx, args, sig_data).await?;
        }
        // Then finally submit everything in one go
        namada.submit(batched_tx, args).await
    }
}

pub async fn submit_bridge_pool_tx<N: Namada>(
    namada: &N,
    args: args::EthereumBridgePool,
) -> Result<(), error::Error> {
    let bridge_pool_tx_data = args.clone().build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, bridge_pool_tx_data.0)?;
    } else {
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &[&args.sender],
            bridge_pool_tx_data,
        )
        .await?;
    }

    Ok(())
}

pub async fn submit_custom<N: Namada>(
    namada: &N,
    args: args::TxCustom,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx {
        return tx::dump_tx(namada.io(), &args.tx, tx);
    }
    if args.tx.dump_wrapper_tx {
        // FIXME: here we attach the inner signatures when dumping the wrapper
        // Attach the provided inner signatures to the tx (if any)
        let signatures = args
            .signatures
            .iter()
            .map(|bytes| {
                tx::SignatureIndex::try_from_json_bytes(bytes).map_err(|err| {
                    error::Error::Encode(error::EncodingError::Serde(
                        err.to_string(),
                    ))
                })
            })
            .collect::<error::Result<Vec<_>>>()?;
        tx.add_signatures(signatures);

        return tx::dump_tx(namada.io(), &args.tx, tx);
    }

    if let Some(signing_data) = signing_data {
        let owners = args
            .owner
            .map_or_else(Default::default, |owner| vec![owner]);
        let refs: Vec<&Address> = owners.iter().collect();
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &refs,
            (tx, signing_data),
        )
        .await?;
    } else {
        // Just submit without the need for signing
        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_update_account<N: Namada>(
    namada: &N,
    args: args::TxUpdateAccount,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_init_account<N: Namada>(
    namada: &N,
    args: args::TxInitAccount,
) -> Result<Option<Address>, error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = tx::build_init_account(namada, &args).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let response = namada.submit(tx, &args.tx).await?;
        if let Some(result) =
            response.is_applied_and_valid(wrapper_hash.as_ref(), &cmt)
        {
            return Ok(result.initialized_accounts.first().cloned());
        }
    }

    Ok(None)
}

pub async fn submit_change_consensus_key(
    namada: &impl Namada,
    args: args::ConsensusKeyChange,
) -> Result<(), error::Error> {
    let validator = args.validator;
    let consensus_key = args.consensus_key;

    // Determine the alias for the new key
    let mut wallet = namada.wallet_mut().await;
    let alias = wallet.find_alias(&validator).cloned();
    let base_consensus_key_alias = alias
        .map(|al| validator_consensus_key(&al))
        .unwrap_or_else(|| {
            validator_consensus_key(&validator.to_string().into())
        });
    let mut consensus_key_alias = base_consensus_key_alias.to_string();
    let all_keys = wallet.get_secret_keys();
    let mut key_counter = 0;
    while all_keys.contains_key(&consensus_key_alias) {
        key_counter += 1;
        consensus_key_alias =
            format!("{base_consensus_key_alias}-{key_counter}");
    }

    // Check the given key or generate a new one
    let new_key = consensus_key
        .map(|key| match key {
            common::PublicKey::Ed25519(_) => key,
            common::PublicKey::Secp256k1(_) => {
                edisplay_line!(
                    namada.io(),
                    "Consensus key can only be ed25519"
                );
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            display_line!(namada.io(), "Generating new consensus key...");
            let password =
                read_and_confirm_encryption_password(args.unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that TM only allows ed25519 for consensus key
                    SchemeType::Ed25519,
                    Some(consensus_key_alias.clone()),
                    args.tx.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });

    // To avoid wallet deadlocks in following operations
    drop(wallet);

    let args = args::ConsensusKeyChange {
        validator: validator.clone(),
        consensus_key: Some(new_key.clone()),
        ..args
    };

    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let resp = namada.submit(tx, &args.tx).await?;

        if !(args.tx.dry_run || args.tx.dry_run_wrapper) {
            if resp
                .is_applied_and_valid(wrapper_hash.as_ref(), &cmt)
                .is_some()
            {
                namada.wallet_mut().await.save().unwrap_or_else(|err| {
                    edisplay_line!(namada.io(), "{}", err)
                });

                display_line!(
                    namada.io(),
                    "New consensus key stored with alias \
                     \"{consensus_key_alias}\". It will become active \
                     {EPOCH_SWITCH_BLOCKS_DELAY} blocks before the start of \
                     the pipeline epoch relative to the current epoch \
                     (current epoch + pipeline offset), at which point you \
                     will need to give the new key to CometBFT in order to be \
                     able to sign with it in consensus.",
                );
            }
        } else {
            display_line!(
                namada.io(),
                "Transaction dry run. No new consensus key has been saved."
            );
        }
    }
    Ok(())
}

pub async fn submit_become_validator(
    namada: &impl Namada,
    config: &mut crate::config::Config,
    args: args::TxBecomeValidator,
) -> Result<(), error::Error> {
    let alias = args
        .tx
        .initialized_account_alias
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "validator".to_string());

    let validator_key_alias = format!("{}-key", alias);
    let consensus_key_alias = validator_consensus_key(&alias.clone().into());
    let protocol_key_alias = format!("{}-protocol-key", alias);
    let eth_hot_key_alias = format!("{}-eth-hot-key", alias);
    let eth_cold_key_alias = format!("{}-eth-cold-key", alias);
    let address_alias = validator_address(&alias.clone().into());

    let mut wallet = namada.wallet_mut().await;
    let consensus_key = args
        .consensus_key
        .clone()
        .map(|key| match key {
            common::PublicKey::Ed25519(_) => key,
            common::PublicKey::Secp256k1(_) => {
                edisplay_line!(
                    namada.io(),
                    "Consensus key can only be ed25519"
                );
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            display_line!(namada.io(), "Generating consensus key...");
            let password =
                read_and_confirm_encryption_password(args.unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that TM only allows ed25519 for consensus key
                    SchemeType::Ed25519,
                    Some(consensus_key_alias.clone().into()),
                    args.tx.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });

    let eth_cold_pk = args
        .eth_cold_key
        .clone()
        .map(|key| match key {
            common::PublicKey::Secp256k1(_) => key,
            common::PublicKey::Ed25519(_) => {
                edisplay_line!(
                    namada.io(),
                    "Eth cold key can only be secp256k1"
                );
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            display_line!(namada.io(), "Generating Eth cold key...");
            let password =
                read_and_confirm_encryption_password(args.unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that ETH only allows secp256k1
                    SchemeType::Secp256k1,
                    Some(eth_cold_key_alias.clone()),
                    args.tx.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });

    let eth_hot_pk = args
        .eth_hot_key
        .clone()
        .map(|key| match key {
            common::PublicKey::Secp256k1(_) => key,
            common::PublicKey::Ed25519(_) => {
                edisplay_line!(
                    namada.io(),
                    "Eth hot key can only be secp256k1"
                );
                safe_exit(1)
            }
        })
        .unwrap_or_else(|| {
            display_line!(namada.io(), "Generating Eth hot key...");
            let password =
                read_and_confirm_encryption_password(args.unsafe_dont_encrypt);
            wallet
                .gen_store_secret_key(
                    // Note that ETH only allows secp256k1
                    SchemeType::Secp256k1,
                    Some(eth_hot_key_alias.clone()),
                    args.tx.wallet_alias_force,
                    password,
                    &mut OsRng,
                )
                .expect("Key generation should not fail.")
                .1
                .ref_to()
        });
    // To avoid wallet deadlocks in following operations
    drop(wallet);

    if args.protocol_key.is_none() {
        display_line!(namada.io(), "Generating protocol signing key...");
    }

    // Generate the validator keys
    let validator_keys = gen_validator_keys(
        &mut *namada.wallet_mut().await,
        Some(eth_hot_pk.clone()),
        args.protocol_key.clone(),
        args.scheme,
    )
    .unwrap();
    let protocol_sk = validator_keys.get_protocol_keypair();
    let protocol_key = protocol_sk.to_public();

    let args = TxBecomeValidator {
        consensus_key: Some(consensus_key.clone()),
        eth_cold_key: Some(eth_cold_pk),
        eth_hot_key: Some(eth_hot_pk),
        protocol_key: Some(protocol_key),
        ..args
    };

    // Store the protocol key in the wallet so that we can sign the tx with it
    // to verify ownership
    display_line!(namada.io(), "Storing protocol key in the wallet...");
    let password =
        read_and_confirm_encryption_password(args.unsafe_dont_encrypt);
    namada
        .wallet_mut()
        .await
        .insert_keypair(
            protocol_key_alias,
            args.tx.wallet_alias_force,
            protocol_sk.clone(),
            password,
            None,
            None,
        )
        .ok_or(error::Error::Other(String::from(
            "Failed to store the keypair.",
        )))?;

    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let resp = namada.submit(tx, &args.tx).await?;

        if args.tx.dry_run || args.tx.dry_run_wrapper {
            display_line!(
                namada.io(),
                "Transaction dry run. No key or addresses have been saved."
            );
            safe_exit(0)
        }

        if resp
            .is_applied_and_valid(wrapper_hash.as_ref(), &cmt)
            .is_none()
        {
            return Err(error::Error::Tx(error::TxSubmitError::Other(
                "Transaction failed. No key or addresses have been saved."
                    .to_string(),
            )));
        }

        // add validator address and keys to the wallet
        let mut wallet = namada.wallet_mut().await;
        wallet.insert_address(
            address_alias.normalize(),
            args.address.clone(),
            false,
        );
        wallet.add_validator_data(args.address.clone(), validator_keys);
        wallet
            .save()
            .unwrap_or_else(|err| edisplay_line!(namada.io(), "{}", err));

        let tendermint_home = config.ledger.cometbft_dir();
        tendermint_node::write_validator_key(
            &tendermint_home,
            &wallet
                .find_key_by_pk(&consensus_key, None)
                .expect("unable to find consensus key pair in the wallet"),
        )
        .unwrap();
        // To avoid wallet deadlocks in following operations
        drop(wallet);
        tendermint_node::write_validator_state(tendermint_home).unwrap();

        // Write Namada config stuff or figure out how to do the above
        // tendermint_node things two epochs in the future!!!
        config.ledger.shell.tendermint_mode = TendermintMode::Validator;
        config
            .write(&config.ledger.shell.base_dir, &config.ledger.chain_id, true)
            .unwrap();

        let pos_params = rpc::query_pos_parameters(namada.client()).await;

        display_line!(namada.io(), "");
        display_line!(
            namada.io(),
            "The keys for validator \"{alias}\" were stored in the wallet:"
        );
        display_line!(
            namada.io(),
            "  Validator account key \"{}\"",
            validator_key_alias
        );
        display_line!(
            namada.io(),
            "  Consensus key \"{}\"",
            consensus_key_alias
        );
        display_line!(
            namada.io(),
            "Your validator address {} has been stored in the wallet with \
             alias \"{}\".",
            args.address,
            address_alias
        );
        display_line!(
            namada.io(),
            "The ledger node has been setup to use this validator's address \
             and consensus key."
        );
        display_line!(
            namada.io(),
            "Your validator will be active in {} epochs. Be sure to restart \
             your node for the changes to take effect!",
            pos_params.pipeline_len
        );
    }
    Ok(())
}

pub async fn submit_init_validator(
    namada: &impl Namada,
    config: &mut crate::config::Config,
    args::TxInitValidator {
        tx: tx_args,
        scheme,
        account_keys,
        threshold,
        consensus_key,
        eth_cold_key,
        eth_hot_key,
        protocol_key,
        commission_rate,
        max_commission_rate_change,
        email,
        website,
        description,
        discord_handle,
        avatar,
        name,
        validator_vp_code_path,
        unsafe_dont_encrypt,
        tx_init_account_code_path,
        tx_become_validator_code_path,
    }: args::TxInitValidator,
) -> Result<(), error::Error> {
    let address = submit_init_account(
        namada,
        args::TxInitAccount {
            tx: tx_args.clone(),
            vp_code_path: validator_vp_code_path,
            tx_code_path: tx_init_account_code_path,
            public_keys: account_keys,
            threshold,
        },
    )
    .await?;

    if tx_args.dry_run || tx_args.dry_run_wrapper {
        eprintln!(
            "Cannot proceed to become validator in dry-run as no account has \
             been created"
        );
        safe_exit(1)
    }
    let address = address.unwrap_or_else(|| {
        eprintln!(
            "Something went wrong with transaction to initialize an account \
             as no address has been created. Cannot proceed to become \
             validator."
        );
        safe_exit(1);
    });

    submit_become_validator(
        namada,
        config,
        args::TxBecomeValidator {
            tx: tx_args,
            address,
            scheme,
            consensus_key,
            eth_cold_key,
            eth_hot_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            email,
            description,
            website,
            discord_handle,
            avatar,
            name,
            tx_code_path: tx_become_validator_code_path,
            unsafe_dont_encrypt,
        },
    )
    .await
}

pub async fn submit_transparent_transfer(
    namada: &impl Namada,
    args: args::TxTransparentTransfer,
) -> Result<(), error::Error> {
    if args.sources.len() > 1 || args.targets.len() > 1 {
        // TODO(namada#3379): Vectorized transfers are not yet supported in the
        // CLI
        return Err(error::Error::Other(
            "Unexpected vectorized transparent transfer".to_string(),
        ));
    }

    let transfer_data = args.clone().build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, transfer_data.0)?;
    } else {
        let reveal_pks: Vec<_> =
            args.sources.iter().map(|datum| &datum.source).collect();
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &reveal_pks,
            transfer_data,
        )
        .await?;
    }

    Ok(())
}

// A mapper that replaces authorization signatures with those in a built-in map
struct MapSaplingSigAuth(
    HashMap<usize, <sapling::Authorized as sapling::Authorization>::AuthSig>,
);

impl sapling::MapAuth<sapling::Authorized, sapling::Authorized>
    for MapSaplingSigAuth
{
    fn map_proof(
        &self,
        p: <sapling::Authorized as sapling::Authorization>::Proof,
        _pos: usize,
    ) -> <sapling::Authorized as sapling::Authorization>::Proof {
        p
    }

    fn map_auth_sig(
        &self,
        s: <sapling::Authorized as sapling::Authorization>::AuthSig,
        pos: usize,
    ) -> <sapling::Authorized as sapling::Authorization>::AuthSig {
        self.0.get(&pos).cloned().unwrap_or(s)
    }

    fn map_authorization(&self, a: sapling::Authorized) -> sapling::Authorized {
        a
    }
}

// Identify the viewing keys in the given transaction for which we do not
// possess spending keys in the software wallet, and augment them with a proof
// generation key from the hardware wallet. Returns a mapping from viewing keys
// to corresponding ZIP 32 paths in the hardware wallet. This function errors
// out if any ZIP 32 path that it handles maps to a different viewing key than
// it does on the software client.
async fn augment_masp_hardware_keys(
    namada: &impl Namada,
    args: &args::Tx,
    sources: impl Iterator<Item = &mut PseudoExtendedKey>,
) -> Result<HashMap<String, ExtendedViewingKey>, error::Error> {
    // Records the shielded keys that are on the hardware wallet
    let mut shielded_hw_keys = HashMap::new();
    // Construct the build parameters that parameterized the Transaction
    // authorizations
    if args.use_device {
        let transport = WalletTransport::from_arg(args.device_transport);
        let app = NamadaApp::new(transport);
        let wallet = namada.wallet().await;
        let mut checked_app_version = false;
        // Augment the pseudo spending key with a proof authorization key
        for source in sources {
            // Only attempt an augmentation if proof authorization is not there
            if source.to_spending_key().is_none() {
                if !checked_app_version {
                    checked_app_version = true;
                    let version = app.version().await.map_err(|err| {
                        error::Error::Other(format!(
                            "Failed to retrieve Ledger app version: {err}"
                        ))
                    })?;
                    if version.major < 3 {
                        edisplay_line!(
                            namada.io(),
                            "Please upgrade the Ledger app to version greater \
                             than or equal to 3.0.0 (got v{}.{}.{}.), due to \
                             a change in modified ZIP32 derivation path. If \
                             you have keys derived using an older versions, \
                             we recommend that you move any funds associated \
                             with them to new keys.",
                            version.major,
                            version.minor,
                            version.patch
                        );
                    }
                }

                // First find the derivation path corresponding to this viewing
                // key
                let viewing_key =
                    ExtendedViewingKey::from(source.to_viewing_key());
                let path = wallet
                    .find_path_by_viewing_key(&viewing_key)
                    .map_err(|err| {
                        error::Error::Other(format!(
                            "Unable to find derivation path from the wallet \
                             for viewing key {}. Error: {}",
                            viewing_key, err,
                        ))
                    })?;
                let path = BIP44Path {
                    path: path.to_string(),
                };
                // Then confirm that the viewing key at this path in the
                // hardware wallet matches the viewing key in this pseudo
                // spending key
                println!(
                    "Requesting viewing key at {} from hardware wallet...",
                    path.path
                );
                let response = app
                    .retrieve_keys(&path, NamadaKeys::ViewKey, true)
                    .await
                    .map_err(|err| {
                        error::Error::Other(format!(
                            "Unable to obtain viewing key from the hardware \
                             wallet at path {}. Error: {}",
                            path.path, err,
                        ))
                    })?;
                let KeyResponse::ViewKey(response_key) = response else {
                    return Err(error::Error::Other(
                        "Unexpected response from Ledger".to_string(),
                    ));
                };
                let xfvk =
                    ExtendedFullViewingKey::try_from_slice(&response_key.xfvk)
                        .expect(
                            "unable to decode extended full viewing key from \
                             the hardware wallet",
                        );
                if ExtendedFullViewingKey::from(viewing_key) != xfvk {
                    return Err(error::Error::Other(format!(
                        "Unexpected viewing key response from Ledger: {}",
                        ExtendedViewingKey::from(xfvk),
                    )));
                }
                // Then obtain the proof authorization key at this path in the
                // hardware wallet
                let response = app
                    .retrieve_keys(&path, NamadaKeys::ProofGenerationKey, false)
                    .await
                    .map_err(|err| {
                        error::Error::Other(format!(
                            "Unable to obtain proof generation key from the \
                             hardware wallet for viewing key {}. Error: {}",
                            viewing_key, err,
                        ))
                    })?;
                let KeyResponse::ProofGenKey(response_key) = response else {
                    return Err(error::Error::Other(
                        "Unexpected response from Ledger".to_string(),
                    ));
                };
                let pgk = ProofGenerationKey::try_from_slice(
                    &[response_key.ak, response_key.nsk].concat(),
                )
                .map_err(|err| {
                    error::Error::Other(format!(
                        "Unexpected proof generation key in response from the \
                         hardware wallet: {}.",
                        err,
                    ))
                })?;
                // Augment the pseudo spending key
                source.augment_proof_generation_key(pgk).map_err(|_| {
                    error::Error::Other(
                        "Proof generation key in response from the hardware \
                         wallet does not correspond to stored viewing key."
                            .to_string(),
                    )
                })?;
                // Finally, augment an incorrect spend authorization key just to
                // make sure that the Transaction is built.
                source.augment_spend_authorizing_key_unchecked(PrivateKey(
                    jubjub::Fr::default(),
                ));
                shielded_hw_keys.insert(path.path, viewing_key);
            }
        }
        Ok(shielded_hw_keys)
    } else {
        Ok(HashMap::new())
    }
}

// If the hardware wallet is beig used, use it to generate the random build
// parameters for the spend, convert, and output descriptions.
async fn generate_masp_build_params(
    spend_len: usize,
    convert_len: usize,
    output_len: usize,
    args: &args::Tx,
) -> Result<Box<dyn BuildParams>, error::Error> {
    // Construct the build parameters that parameterized the Transaction
    // authorizations
    if args.use_device {
        let transport = WalletTransport::from_arg(args.device_transport);
        let app = NamadaApp::new(transport);
        // Clear hardware wallet randomness buffers
        app.clean_randomness_buffers().await.map_err(|err| {
            error::Error::Other(format!(
                "Unable to clear randomness buffer. Error: {}",
                err,
            ))
        })?;
        // Get randomness to aid in construction of various descriptors
        let mut bparams = StoredBuildParams::default();
        for _ in 0..spend_len {
            let spend_randomness = app
                .get_spend_randomness()
                .await
                .map_err(|err| error::Error::Other(err.to_string()))?;
            bparams.spend_params.push(SpendBuildParams {
                rcv: jubjub::Fr::from_bytes(&spend_randomness.rcv).unwrap(),
                alpha: jubjub::Fr::from_bytes(&spend_randomness.alpha).unwrap(),
            });
        }
        for _ in 0..convert_len {
            let convert_randomness = app
                .get_convert_randomness()
                .await
                .map_err(|err| error::Error::Other(err.to_string()))?;
            bparams.convert_params.push(ConvertBuildParams {
                rcv: jubjub::Fr::from_bytes(&convert_randomness.rcv).unwrap(),
            });
        }
        for _ in 0..output_len {
            let output_randomness = app
                .get_output_randomness()
                .await
                .map_err(|err| error::Error::Other(err.to_string()))?;
            bparams.output_params.push(OutputBuildParams {
                rcv: jubjub::Fr::from_bytes(&output_randomness.rcv).unwrap(),
                rseed: output_randomness.rcm,
                ..OutputBuildParams::default()
            });
        }
        Ok(Box::new(bparams))
    } else {
        Ok(Box::new(RngBuildParams::new(OsRng)))
    }
}

// Sign the given transaction's MASP component using signatures produced by the
// hardware wallet. This function takes the list of spending keys that are
// hosted on the hardware wallet.
async fn masp_sign(
    tx: &mut Tx,
    args: &args::Tx,
    signing_data: &SigningTxData,
    shielded_hw_keys: HashMap<String, ExtendedViewingKey>,
) -> Result<(), error::Error> {
    // Get the MASP section that is the target of our signing
    if let Some(shielded_hash) = signing_data.shielded_hash {
        let mut masp_tx = tx
            .get_masp_section(&shielded_hash)
            .expect("Expected to find the indicated MASP Transaction")
            .clone();

        let masp_builder = tx
            .get_masp_builder(&shielded_hash)
            .expect("Expected to find the indicated MASP Builder");

        // Reverse the spend metadata to enable looking up construction
        // material
        let sapling_inputs = masp_builder.builder.sapling_inputs();
        let mut descriptor_map = vec![0; sapling_inputs.len()];
        for i in 0.. {
            if let Some(pos) = masp_builder.metadata.spend_index(i) {
                descriptor_map[pos] = i;
            } else {
                break;
            };
        }
        // Sign the MASP Transaction using each relevant key in the
        // hardware wallet
        let mut app = None;
        for (path, vk) in shielded_hw_keys {
            // Initialize the Ledger app interface if it is uninitialized
            let app = app.get_or_insert_with(|| {
                NamadaApp::new(WalletTransport::from_arg(args.device_transport))
            });
            // Sign the MASP Transaction using the current viewing key
            let path = BIP44Path {
                path: path.to_string(),
            };
            println!(
                "Requesting that hardware wallet sign shielded transfer with \
                 spending key at {}...",
                path.path
            );
            app.sign_masp_spends(&path, &tx.serialize_to_vec())
                .await
                .map_err(|err| error::Error::Other(err.to_string()))?;
            // Now prepare a new list of authorizations based on hardware
            // wallet responses
            let mut authorizations = HashMap::new();
            for (tx_pos, builder_pos) in descriptor_map.iter().enumerate() {
                // Read the next spend authorization signature from the
                // hardware wallet
                let response = app
                    .get_spend_signature()
                    .await
                    .map_err(|err| error::Error::Other(err.to_string()))?;
                let signature = redjubjub::Signature::try_from_slice(
                    &[response.rbar, response.sbar].concat(),
                )
                .map_err(|err| {
                    error::Error::Other(format!(
                        "Unexpected spend authorization key in response from \
                         the hardware wallet: {}.",
                        err,
                    ))
                })?;
                if *sapling_inputs[*builder_pos].key()
                    == ExtendedFullViewingKey::from(vk)
                {
                    // If this descriptor was produced by the current
                    // viewing key (which comes from the hardware wallet),
                    // then use the authorization from the hardware wallet
                    authorizations.insert(tx_pos, signature);
                }
            }
            // Finally, patch the MASP Transaction with the fetched spend
            // authorization signature
            masp_tx = (*masp_tx)
                .clone()
                .map_authorization::<masp_primitives::transaction::Authorized>(
                    (),
                    MapSaplingSigAuth(authorizations),
                )
                .freeze()
                .map_err(|err| {
                    error::Error::Other(format!(
                        "Unable to apply hardware walleet sourced \
                         authorization signatures to the transaction being \
                         constructed: {}.",
                        err,
                    ))
                })?;
        }
        tx.remove_masp_section(&shielded_hash);
        tx.add_section(Section::MaspTx(masp_tx));
    }
    Ok(())
}

pub async fn submit_shielded_transfer(
    namada: &impl Namada,
    mut args: args::TxShieldedTransfer,
) -> Result<(), error::Error> {
    display_line!(
        namada.io(),
        "{}: {}\n",
        "WARNING".bold().underline().yellow(),
        "Some information might be leaked if your shielded wallet is not up \
         to date, make sure to run `namadac shielded-sync` before running \
         this command.",
    );

    let sources = args
        .sources
        .iter_mut()
        .map(|x| &mut x.source)
        .chain(args.gas_spending_key.iter_mut());
    let shielded_hw_keys =
        augment_masp_hardware_keys(namada, &args.tx, sources).await?;
    let mut bparams = generate_masp_build_params(
        MAX_HW_SPEND,
        MAX_HW_CONVERT,
        MAX_HW_OUTPUT,
        &args.tx,
    )
    .await?;
    let (mut tx, signing_data) =
        args.clone().build(namada, &mut bparams).await?;
    let disposable_fee_payer = match signing_data {
        SigningData::Inner(_) => false,
        SigningData::Wrapper(ref signing_wrapper_data) => {
            signing_wrapper_data.disposable_fee_payer()
        }
    };
    if !disposable_fee_payer {
        display_line!(
            namada.io(),
            "{}: {}\n",
            "WARNING".bold().underline().yellow(),
            "Using a transparent gas payer for a shielded transaction will \
             most likely leak information: please consider paying the gas \
             fees via the MASP with a disposable gas payer.",
        );
    }
    masp_sign(
        &mut tx,
        &args.tx,
        signing_data
            .signing_tx_data()
            .expect("Missing expected signing data"),
        shielded_hw_keys,
    )
    .await?;

    let masp_section = tx
        .sections
        .iter()
        .find_map(|section| section.masp_tx())
        .ok_or_else(|| {
            error::Error::Other(
                "Missing MASP section in shielded transaction".to_string(),
            )
        })?;
    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        if disposable_fee_payer {
            display_line!(
                namada.io(),
                "Transaction dry run. The disposable address will not be \
                 saved to wallet."
            )
        }
        tx::dump_tx(namada.io(), &args.tx, tx)?;
        pre_cache_masp_data(namada, &masp_section).await;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        // Store the generated disposable signing key to wallet in case of need
        if disposable_fee_payer {
            namada.wallet().await.save().map_err(|_| {
                error::Error::Other(
                    "Failed to save disposable address to wallet".to_string(),
                )
            })?;
        }
        let res = namada.submit(tx, &args.tx).await?;
        pre_cache_masp_data_on_tx_result(namada, &res, &masp_section).await;
    }
    Ok(())
}

pub async fn submit_shielding_transfer(
    namada: &impl Namada,
    args: args::TxShieldingTransfer,
) -> Result<(), error::Error> {
    // Repeat once if the tx fails on a crossover of an epoch
    for _ in 0..2 {
        let mut bparams = generate_masp_build_params(
            MAX_HW_SPEND,
            MAX_HW_CONVERT,
            MAX_HW_OUTPUT,
            &args.tx,
        )
        .await?;
        let (tx, signing_data, tx_epoch) =
            args.clone().build(namada, &mut bparams).await?;

        if args.tx.dump_tx || args.tx.dump_wrapper_tx {
            tx::dump_tx(namada.io(), &args.tx, tx)?;
            break;
        }

        let cmt_hash = tx.commitments().last().unwrap().get_hash();
        let wrapper_hash = tx.wrapper_hash();

        let reveal_pks: Vec<_> =
            args.sources.iter().map(|datum| &datum.source).collect();
        let result = batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &reveal_pks,
            (tx, signing_data),
        )
        .await?;

        // Check the need for a resubmission
        if let ProcessTxResponse::Applied(resp) = result {
            if let Some(InnerTxResult::VpsRejected(result)) =
                resp.batch_result().get(&compute_inner_tx_hash(
                    wrapper_hash.as_ref(),
                    either::Left(&cmt_hash),
                ))
            {
                let rejected_vps = &result.vps_result.rejected_vps;
                let vps_errors = &result.vps_result.errors;
                // If the transaction is rejected by the MASP VP only and
                // because of an asset's epoch issue
                if rejected_vps.len() == 1
                    && (vps_errors.contains(&(
                        MASP,
                        "Native VP error: epoch is missing from asset type"
                            .to_string(),
                    )) || vps_errors.contains(&(
                        MASP,
                        "Native VP error: Unable to decode asset type"
                            .to_string(),
                    )))
                {
                    let submission_masp_epoch =
                        rpc::query_and_print_masp_epoch(namada).await;
                    // And its submission epoch doesn't match construction
                    // epoch
                    if tx_epoch != submission_masp_epoch {
                        // Then we probably straddled an epoch boundary.
                        // Let's retry...
                        edisplay_line!(
                            namada.io(),
                            "Shielding transaction rejected and this may be \
                             due to the epoch changing. Attempting to \
                             resubmit transaction.",
                        );
                        continue;
                    }
                }
            }
        }

        // Otherwise either the transaction was successful or it will not
        // benefit from resubmission
        break;
    }
    Ok(())
}

pub async fn submit_unshielding_transfer(
    namada: &impl Namada,
    mut args: args::TxUnshieldingTransfer,
) -> Result<(), error::Error> {
    display_line!(
        namada.io(),
        "{}: {}\n",
        "WARNING".bold().underline().yellow(),
        "Some information might be leaked if your shielded wallet is not up \
         to date, make sure to run `namadac shielded-sync` before running \
         this command.",
    );

    let sources = args
        .sources
        .iter_mut()
        .map(|x| &mut x.source)
        .chain(args.gas_spending_key.iter_mut());
    let shielded_hw_keys =
        augment_masp_hardware_keys(namada, &args.tx, sources).await?;
    let mut bparams = generate_masp_build_params(
        MAX_HW_SPEND,
        MAX_HW_CONVERT,
        MAX_HW_OUTPUT,
        &args.tx,
    )
    .await?;
    let (mut tx, signing_data) =
        args.clone().build(namada, &mut bparams).await?;
    let disposable_fee_payer = match signing_data {
        SigningData::Inner(_) => false,
        SigningData::Wrapper(ref signing_wrapper_data) => {
            signing_wrapper_data.disposable_fee_payer()
        }
    };
    if !disposable_fee_payer {
        display_line!(
            namada.io(),
            "{}: {}\n",
            "WARNING".bold().underline().yellow(),
            "Using a transparent gas payer for an unshielding transaction \
             will most likely leak information: please consider paying the \
             gas fees via the MASP with a disposable gas payer.",
        );
    }
    masp_sign(
        &mut tx,
        &args.tx,
        signing_data
            .signing_tx_data()
            .expect("Missing signing data"),
        shielded_hw_keys,
    )
    .await?;

    let masp_section = tx
        .sections
        .iter()
        .find_map(|section| section.masp_tx())
        .ok_or_else(|| {
            error::Error::Other(
                "Missing MASP section in shielded transaction".to_string(),
            )
        })?;
    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        if disposable_fee_payer {
            display_line!(
                namada.io(),
                "Transaction dry run. The disposable address will not be \
                 saved to wallet."
            )
        }
        tx::dump_tx(namada.io(), &args.tx, tx)?;
        pre_cache_masp_data(namada, &masp_section).await;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        // Store the generated disposable signing key to wallet in case of need
        if disposable_fee_payer {
            namada.wallet().await.save().map_err(|_| {
                error::Error::Other(
                    "Failed to save disposable address to wallet".to_string(),
                )
            })?;
        }
        let res = namada.submit(tx, &args.tx).await?;
        pre_cache_masp_data_on_tx_result(namada, &res, &masp_section).await;
    }
    Ok(())
}

pub async fn submit_ibc_transfer<N: Namada>(
    namada: &N,
    mut args: args::TxIbcTransfer,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let sources = args
        .source
        .spending_key_mut()
        .into_iter()
        .chain(args.gas_spending_key.iter_mut());
    let shielded_hw_keys =
        augment_masp_hardware_keys(namada, &args.tx, sources).await?;
    // Try to generate MASP build parameters. This might fail when using a
    // hardware wallet if it does not support MASP operations.
    let bparams_result = generate_masp_build_params(
        MAX_HW_SPEND,
        MAX_HW_CONVERT,
        MAX_HW_OUTPUT,
        &args.tx,
    )
    .await;
    // If MASP build parameter generation failed for any reason, then try to
    // build the transaction with no parameters. Remember the error though.
    let (mut bparams, bparams_err) = bparams_result.map_or_else(
        |e| (Box::new(StoredBuildParams::default()) as _, Some(e)),
        |bparams| (bparams, None),
    );
    // If transaction building fails for any reason, then abort the process
    // blaming MASP build parameter generation if that had also failed.
    let (mut tx, signing_data, _) = args
        .build(namada, &mut bparams)
        .await
        .map_err(|e| bparams_err.unwrap_or(e))?;
    let disposable_fee_payer = match signing_data {
        SigningData::Inner(_) => false,
        SigningData::Wrapper(ref signing_wrapper_data) => {
            signing_wrapper_data.disposable_fee_payer()
        }
    };
    if args.source.spending_key().is_some() && !disposable_fee_payer {
        display_line!(
            namada.io(),
            "{}: {}\n",
            "WARNING".bold().underline().yellow(),
            "Using a transparent gas payer for an unshielding ibc transaction \
             will most likely leak information: please consider paying the \
             gas fees via the MASP with a disposable gas payer.",
        );
    }
    // Any effects of a MASP build parameter generation failure would have
    // manifested during transaction building. So we discount that as a root
    // cause from now on.
    masp_sign(
        &mut tx,
        &args.tx,
        signing_data
            .signing_tx_data()
            .expect("Missing expected signing data"),
        shielded_hw_keys,
    )
    .await?;

    let opt_masp_section =
        tx.sections.iter().find_map(|section| section.masp_tx());
    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
        if disposable_fee_payer {
            display_line!(
                namada.io(),
                "Transaction dry run. The disposable address will not be \
                 saved to wallet."
            )
        }
        if let Some(masp_section) = opt_masp_section {
            pre_cache_masp_data(namada, &masp_section).await;
        }
    } else {
        // Store the generated disposable signing key to wallet in case of need
        if disposable_fee_payer {
            namada.wallet().await.save().map_err(|_| {
                error::Error::Other(
                    "Failed to save disposable address to wallet".to_string(),
                )
            })?;
        }
        let res = batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &[&args.source.effective_address()],
            (tx, signing_data),
        )
        .await?;

        if let Some(masp_section) = opt_masp_section {
            pre_cache_masp_data_on_tx_result(namada, &res, &masp_section).await;
        }
    }
    // NOTE that the tx could fail when its submission epoch doesn't match
    // construction epoch

    Ok(())
}

pub async fn submit_init_proposal<N: Namada>(
    namada: &N,
    args: args::InitProposal,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let current_epoch = rpc::query_and_print_epoch(namada).await;
    let governance_parameters =
        rpc::query_governance_parameters(namada.client()).await;
    let (proposal_tx_data, proposal_author) = if args.is_pgf_funding {
        let proposal =
            PgfFundingProposal::try_from(args.proposal_data.as_ref())
                .map_err(|e| {
                    error::TxSubmitError::FailedGovernaneProposalDeserialize(
                        e.to_string(),
                    )
                })?
                .validate(&governance_parameters, current_epoch, args.tx.force)
                .map_err(|e| {
                    error::TxSubmitError::InvalidProposal(e.to_string())
                })?;
        let proposal_author = proposal.proposal.author.clone();

        (
            tx::build_pgf_funding_proposal(namada, &args, proposal).await?,
            proposal_author,
        )
    } else if args.is_pgf_stewards {
        let proposal = PgfStewardProposal::try_from(
            args.proposal_data.as_ref(),
        )
        .map_err(|e| {
            error::TxSubmitError::FailedGovernaneProposalDeserialize(
                e.to_string(),
            )
        })?;
        let author_balance = namada_sdk::rpc::get_token_balance(
            namada.client(),
            &namada.native_token(),
            &proposal.proposal.author,
            None,
        )
        .await
        .unwrap();
        let proposal = proposal
            .validate(
                &governance_parameters,
                current_epoch,
                author_balance,
                args.tx.force,
            )
            .map_err(|e| {
                error::TxSubmitError::InvalidProposal(e.to_string())
            })?;
        let proposal_author = proposal.proposal.author.clone();

        (
            tx::build_pgf_stewards_proposal(namada, &args, proposal).await?,
            proposal_author,
        )
    } else {
        let proposal = DefaultProposal::try_from(args.proposal_data.as_ref())
            .map_err(|e| {
            error::TxSubmitError::FailedGovernaneProposalDeserialize(
                e.to_string(),
            )
        })?;
        let author_balance = namada_sdk::rpc::get_token_balance(
            namada.client(),
            &namada.native_token(),
            &proposal.proposal.author,
            None,
        )
        .await
        .unwrap();
        let proposal = proposal
            .validate(
                &governance_parameters,
                current_epoch,
                author_balance,
                args.tx.force,
            )
            .map_err(|e| {
                error::TxSubmitError::InvalidProposal(e.to_string())
            })?;
        let proposal_author = proposal.proposal.author.clone();

        (
            tx::build_default_proposal(namada, &args, proposal).await?,
            proposal_author,
        )
    };

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, proposal_tx_data.0)?;
    } else {
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &[&proposal_author],
            proposal_tx_data,
        )
        .await?;
    }

    Ok(())
}

pub async fn submit_vote_proposal<N: Namada>(
    namada: &N,
    args: args::VoteProposal,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let submit_vote_proposal_data = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, submit_vote_proposal_data.0)?;
    } else {
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &[&args.voter_address],
            submit_vote_proposal_data,
        )
        .await?;
    }

    Ok(())
}

pub async fn submit_reveal_pk<N: Namada>(
    namada: &N,
    args: args::RevealPk,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        let tx_data =
            tx::build_reveal_pk(namada, &args.tx, &args.public_key).await?;
        tx::dump_tx(namada.io(), &args.tx, tx_data.0.clone())?;
    } else {
        let tx_data =
            submit_reveal_aux(namada, &args.tx, &(&args.public_key).into())
                .await?;

        if let Some((mut tx, signing_data)) = tx_data {
            sign(namada, &mut tx, &args.tx, signing_data).await?;
            namada.submit(tx, &args.tx).await?;
        }
    }

    Ok(())
}

pub async fn submit_bond<N: Namada>(
    namada: &N,
    args: args::Bond,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let submit_bond_tx_data = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, submit_bond_tx_data.0)?;
    } else {
        let default_address = args.source.as_ref().unwrap_or(&args.validator);
        batch_opt_reveal_pk_and_submit(
            namada,
            &args.tx,
            &[default_address],
            submit_bond_tx_data,
        )
        .await?;
    }

    Ok(())
}

pub async fn submit_unbond<N: Namada>(
    namada: &N,
    args: args::Unbond,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data, latest_withdrawal_pre) =
        args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;
        let cmt = tx.first_commitments().unwrap().to_owned();
        let wrapper_hash = tx.wrapper_hash();
        let resp = namada.submit(tx, &args.tx).await?;

        if !(args.tx.dry_run || args.tx.dry_run_wrapper)
            && resp
                .is_applied_and_valid(wrapper_hash.as_ref(), &cmt)
                .is_some()
        {
            tx::query_unbonds(namada, args.clone(), latest_withdrawal_pre)
                .await?;
        }
    }

    Ok(())
}

pub async fn submit_withdraw<N: Namada>(
    namada: &N,
    args: args::Withdraw,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_claim_rewards<N: Namada>(
    namada: &N,
    args: args::ClaimRewards,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_redelegate<N: Namada>(
    namada: &N,
    args: args::Redelegate,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_validator_commission_change<N: Namada>(
    namada: &N,
    args: args::CommissionRateChange,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_validator_metadata_change<N: Namada>(
    namada: &N,
    args: args::MetaDataChange,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_unjail_validator<N: Namada>(
    namada: &N,
    args: args::TxUnjailValidator,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_deactivate_validator<N: Namada>(
    namada: &N,
    args: args::TxDeactivateValidator,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_reactivate_validator<N: Namada>(
    namada: &N,
    args: args::TxReactivateValidator,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_update_steward_commission<N: Namada>(
    namada: &N,
    args: args::UpdateStewardCommission,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

pub async fn submit_resign_steward<N: Namada>(
    namada: &N,
    args: args::ResignSteward,
) -> Result<(), error::Error>
where
    <N::Client as namada_sdk::io::Client>::Error: std::fmt::Display,
{
    let (mut tx, signing_data) = args.build(namada).await?;

    if args.tx.dump_tx || args.tx.dump_wrapper_tx {
        tx::dump_tx(namada.io(), &args.tx, tx)?;
    } else {
        sign(namada, &mut tx, &args.tx, signing_data).await?;

        namada.submit(tx, &args.tx).await?;
    }

    Ok(())
}

/// Save accounts initialized from a tx into the wallet, if any.
pub async fn save_initialized_accounts(
    namada: &impl Namada,
    args: &args::Tx,
    initialized_accounts: Vec<Address>,
) {
    tx::save_initialized_accounts(namada, args, initialized_accounts).await
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a validator
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx(
    namada: &impl Namada,
    to_broadcast: &TxBroadcastData,
) -> Result<Response, error::Error> {
    tx::broadcast_tx(namada, to_broadcast).await
}

/// Broadcast a transaction to be included in the blockchain.
///
/// Checks that
/// 1. The tx has been successfully included into the mempool of a validator
/// 2. The tx has been included on the blockchain
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn submit_tx(
    namada: &impl Namada,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse, error::Error> {
    tx::submit_tx(namada, to_broadcast).await
}

/// Generate MASP transaction and output it
pub async fn gen_ibc_shielding_transfer(
    context: &impl Namada,
    args: args::GenIbcShieldingTransfer,
) -> Result<(), error::Error> {
    let output_folder = args.output_folder.clone();

    if let Some(masp_tx) = tx::gen_ibc_shielding_transfer(context, args).await?
    {
        let tx_id = masp_tx.txid().to_string();
        let filename = format!("ibc_masp_tx_{}.memo", tx_id);
        let output_path = match output_folder {
            Some(path) => path.join(filename),
            None => filename.into(),
        };
        let mut out = File::create(&output_path)
            .expect("Creating a new file for IBC MASP transaction failed.");
        let bytes = convert_masp_tx_to_ibc_memo(&masp_tx);
        out.write_all(bytes.as_bytes())
            .expect("Writing IBC MASP transaction file failed.");
        println!(
            "Output IBC shielding transfer for {tx_id} to {}",
            output_path.to_string_lossy()
        );
    } else {
        eprintln!("No shielded transfer for this IBC transfer.")
    }
    Ok(())
}

// Pre-cache the data for the provided MASP transaction. Log an error on
// failure.
async fn pre_cache_masp_data(namada: &impl Namada, masp_tx: &MaspTransaction) {
    if let Err(e) = namada
        .shielded_mut()
        .await
        .pre_cache_transaction(masp_tx)
        .await
    {
        // Just display the error but do not propagate it
        edisplay_line!(namada.io(), "Failed to pre-cache masp data: {}.", e);
    }
}

// Check the result of a transaction and pre-cache the masp data accordingly
async fn pre_cache_masp_data_on_tx_result(
    namada: &impl Namada,
    tx_result: &ProcessTxResponse,
    masp_tx: &MaspTransaction,
) {
    match tx_result {
        ProcessTxResponse::Applied(resp) => {
            if let Some(InnerTxResult::Success(_)) =
                // If we have the masp data in an ibc transfer it
                // means we are unshielding, so there's no reveal pk
                // tx in the batch which contains only the ibc tx
                resp.batch_result().first().map(|(_, res)| res)
            {
                pre_cache_masp_data(namada, masp_tx).await;
            }
        }
        ProcessTxResponse::Broadcast(_) => {
            pre_cache_masp_data(namada, masp_tx).await;
        }
        // Do not pre-cache when dry-running
        ProcessTxResponse::DryRun(_) => {}
    }
}
