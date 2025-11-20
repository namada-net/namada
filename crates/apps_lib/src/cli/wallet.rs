//! Namada Wallet CLI.

use std::fs::File;
use std::io::{self, Write};
use std::str::FromStr;

use color_eyre::eyre::Result;
use itertools::sorted;
use ledger_namada_rs::{BIP44Path, KeyResponse, NamadaApp, NamadaKeys};
use ledger_transport_hid::TransportNativeHID;
use ledger_transport_hid::hidapi::HidApi;
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada_core::chain::BlockHeight;
use namada_core::masp::{
    DiversifierIndex, ExtendedSpendingKey, MaspValue, PaymentAddress,
};
use namada_sdk::address::{Address, DecodeError};
use namada_sdk::borsh::{BorshDeserialize, BorshSerializeExt};
use namada_sdk::io::{Io, display_line, edisplay_line};
use namada_sdk::key::*;
use namada_sdk::wallet::{
    DecryptionError, DerivationPath, DerivationPathError, FindKeyError, Wallet,
};
use rand_core::OsRng;

use crate::cli;
use crate::cli::api::CliApi;
use crate::cli::args::CliToSdk;
use crate::cli::{Context, args, cmds};
use crate::client::utils::PRE_GENESIS_DIR;
use crate::tendermint_node::validator_key_to_json;
use crate::wallet::{
    self, CliWalletUtils, WalletTransport, read_and_confirm_encryption_password,
};

impl CliApi {
    pub async fn handle_wallet_command(
        cmd: cmds::NamadaWallet,
        mut ctx: Context,
        io: &impl Io,
    ) -> Result<()> {
        match cmd {
            cmds::NamadaWallet::KeyGen(cmds::WalletGen(args)) => {
                key_gen(ctx, io, args)
            }
            cmds::NamadaWallet::KeyDerive(cmds::WalletDerive(args)) => {
                key_derive(ctx, io, args).await
            }
            cmds::NamadaWallet::KeyAddrList(cmds::WalletListKeysAddresses(
                args,
            )) => key_address_list(ctx, io, args),
            cmds::NamadaWallet::KeyAddrFind(cmds::WalletFindKeysAddresses(
                args,
            )) => key_address_find(ctx, io, args),
            cmds::NamadaWallet::KeyExport(cmds::WalletExportKey(args)) => {
                key_export(ctx, io, args)
            }
            cmds::NamadaWallet::KeyConvert(cmds::WalletConvertKey(args)) => {
                key_convert(ctx, io, args)
            }
            cmds::NamadaWallet::KeyImport(cmds::WalletImportKey(args)) => {
                key_import(ctx, io, args)
            }
            cmds::NamadaWallet::KeyAddrAdd(cmds::WalletAddKeyAddress(args)) => {
                key_address_add(ctx, io, args)
            }
            cmds::NamadaWallet::KeyAddrRemove(
                cmds::WalletRemoveKeyAddress(args),
            ) => key_address_remove(ctx, io, args),
            cmds::NamadaWallet::PayAddrGen(cmds::WalletGenPaymentAddress(
                args,
            )) => {
                let args = args.to_sdk(&mut ctx)?;
                payment_address_gen(ctx, io, args)
            }
        }
        Ok(())
    }
}

/// List shielded keys.
fn shielded_keys_list(
    wallet: &Wallet<CliWalletUtils>,
    io: &impl Io,
    decrypt: bool,
    unsafe_show_secret: bool,
    show_hint: bool,
) {
    let known_view_keys = wallet.get_viewing_keys();
    let known_spend_keys = wallet.get_spending_keys();
    if known_view_keys.is_empty() {
        if show_hint {
            display_line!(
                io,
                "No known keys. Try `add --alias my-addr --value ...` to add \
                 a new key to the wallet, or `gen --shielded --alias my-key` \
                 to generate a new key.",
            );
        }
    } else {
        let mut w_lock = io::stdout().lock();
        display_line!(io, &mut w_lock; "Known shielded keys:").unwrap();
        for (alias, key) in known_view_keys {
            let spending_key_opt = known_spend_keys.get(&alias);
            // If this alias is associated with a spending key, indicate whether
            // or not the spending key is encrypted
            let encrypted_status = match spending_key_opt {
                None => "external",
                Some(spend_key) if spend_key.is_encrypted() => "encrypted",
                _ => "not encrypted",
            };
            display_line!(io, &mut w_lock; "  Alias \"{}\" ({}):", alias, encrypted_status).unwrap();
            // Always print the corresponding viewing key
            display_line!(io, &mut w_lock; "    Viewing Key: {}", key).unwrap();
            // A subset of viewing keys will have corresponding spending keys.
            // Print those too if they are available and requested.
            if let Some(spending_key) = spending_key_opt {
                match spending_key.get::<CliWalletUtils>(
                    decrypt,
                    None,
                    Some(&alias),
                ) {
                    // Here the spending key is unencrypted or successfully
                    // decrypted
                    Ok(spending_key) => {
                        if unsafe_show_secret {
                            display_line!(io,
                                &mut w_lock;
                                "    Spending key: {}", spending_key,
                            )
                            .unwrap();
                        }
                    }
                    // Here the key is encrypted but decryption has not been
                    // requested
                    Err(DecryptionError::NotDecrypting) if !decrypt => {
                        continue;
                    }
                    // Here the key is encrypted but no password has been
                    // provided
                    Err(DecryptionError::EmptyPassword) => {
                        display_line!(io,
                                      &mut w_lock;
                                      "Decryption of the spending key cancelled: no password provided"
                        )
                        .unwrap();
                    }
                    // Here the key is encrypted but incorrect password has
                    // been provided
                    Err(err) => {
                        display_line!(io,
                            &mut w_lock;
                                "    Couldn't decrypt the spending key: {}",
                                err,
                        )
                        .unwrap();
                    }
                }
            }
        }
    }
}

/// List payment addresses.
fn payment_addresses_list(
    wallet: &Wallet<CliWalletUtils>,
    io: &impl Io,
    show_hint: bool,
) {
    let known_addresses = wallet.get_payment_addrs();
    if known_addresses.is_empty() {
        if show_hint {
            display_line!(
                io,
                "No known payment addresses. Try `gen-payment-addr --alias \
                 my-payment-addr` to generate a new payment address.",
            );
        }
    } else {
        let mut w_lock = io::stdout().lock();
        display_line!(io, &mut w_lock; "Known payment addresses:").unwrap();
        for (alias, address) in sorted(known_addresses) {
            display_line!(io, &mut w_lock; "  \"{}\": {}", alias, address)
                .unwrap();
        }
    }
}

/// Derives a masp spending key from the mnemonic code in the wallet.
async fn shielded_key_derive(
    ctx: Context,
    io: &impl Io,
    args::KeyDerive {
        alias,
        alias_force,
        unsafe_dont_encrypt,
        unsafe_pure_zip32,
        derivation_path,
        allow_non_compliant,
        prompt_bip39_passphrase,
        use_device,
        birthday,
        ..
    }: args::KeyDerive,
) {
    let mut wallet = load_wallet(ctx);
    if !unsafe_pure_zip32 {
        tracing::warn!(
            "The default shielded key derivation algorithm has been changed \
             to achieve hardware wallet compatibility. For information on the \
             deprecated algorithm, see the documentation for \
             --unsafe-pure-zip32."
        );
    }
    let derivation_path = decode_shielded_derivation_path(derivation_path)
        .unwrap_or_else(|err| {
            edisplay_line!(io, "{}", err);
            cli::safe_exit(1)
        });
    println!("Using HD derivation path {}", derivation_path);
    if !allow_non_compliant && !derivation_path.is_namada_shielded_compliant() {
        display_line!(io, "Path {} is not compliant.", derivation_path);
        display_line!(io, "No changes are persisted. Exiting.");
        cli::safe_exit(1)
    }
    let alias = alias.to_lowercase();
    let alias = if !use_device {
        let encryption_password =
            read_and_confirm_encryption_password(unsafe_dont_encrypt);
        wallet
            .derive_store_spending_key_from_mnemonic_code(
                alias,
                alias_force,
                birthday,
                unsafe_pure_zip32,
                derivation_path,
                None,
                prompt_bip39_passphrase,
                encryption_password,
            )
            .unwrap_or_else(|| {
                edisplay_line!(io, "Failed to derive a key.");
                display_line!(io, "No changes are persisted. Exiting.");
                cli::safe_exit(1)
            })
            .0
    } else {
        let hidapi = HidApi::new().unwrap_or_else(|err| {
            edisplay_line!(io, "Failed to create HidApi: {}", err);
            cli::safe_exit(1)
        });
        let app = NamadaApp::new(
            TransportNativeHID::new(&hidapi).unwrap_or_else(|err| {
                edisplay_line!(io, "Unable to connect to Ledger: {}", err);
                cli::safe_exit(1)
            }),
        );
        let version = app.version().await.unwrap_or_else(|err| {
            edisplay_line!(io, "Failed to retrieve Ledger app version: {err}");
            cli::safe_exit(1)
        });
        if version.major < 3 {
            edisplay_line!(
                io,
                "Minimum supported Ledger app version is 3.0.0 due to a \
                 change in modified ZIP32 derivation path. Got v{}.{}.{}.",
                version.major,
                version.minor,
                version.patch
            );
            cli::safe_exit(1)
        }

        let response = app
            .retrieve_keys(
                &BIP44Path {
                    path: derivation_path.to_string(),
                },
                NamadaKeys::ViewKey,
                true,
            )
            .await
            .unwrap_or_else(|err| {
                edisplay_line!(
                    io,
                    "Unable to connect to query address and public key from \
                     Ledger: {}",
                    err
                );
                cli::safe_exit(1)
            });
        let KeyResponse::ViewKey(response_key) = response else {
            edisplay_line!(io, "Unexpected response from Ledger");
            cli::safe_exit(1)
        };
        let xfvk = ExtendedFullViewingKey::try_from_slice(&response_key.xfvk)
            .expect(
                "unable to decode extended full viewing key from the hardware \
                 wallet",
            );

        wallet
            .insert_viewing_key(
                alias,
                xfvk.into(),
                birthday,
                alias_force,
                Some(derivation_path),
            )
            .unwrap_or_else(|| {
                display_line!(io, "No changes are persisted. Exiting.");
                cli::safe_exit(1)
            })
    };
    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(
        io,
        "Successfully added a key and an address with alias: \"{}\"",
        alias
    );
}

/// Generate a spending key.
fn shielded_key_gen(
    ctx: Context,
    io: &impl Io,
    args::KeyGen {
        raw,
        alias,
        alias_force,
        unsafe_dont_encrypt,
        derivation_path,
        allow_non_compliant,
        prompt_bip39_passphrase,
        birthday,
        ..
    }: args::KeyGen,
) {
    let mut wallet = load_wallet(ctx);
    let alias = alias.to_lowercase();
    let password = read_and_confirm_encryption_password(unsafe_dont_encrypt);
    let alias = if raw {
        wallet.gen_store_spending_key(
            alias,
            birthday,
            password,
            alias_force,
            &mut OsRng,
        )
    } else {
        let derivation_path = decode_shielded_derivation_path(derivation_path)
            .unwrap_or_else(|err| {
                edisplay_line!(io, "{}", err);
                cli::safe_exit(1)
            });
        println!("Using HD derivation path {}", derivation_path);
        if !allow_non_compliant
            && !derivation_path.is_namada_shielded_compliant()
        {
            display_line!(io, "Path {} is not compliant.", derivation_path);
            display_line!(io, "No changes are persisted. Exiting.");
            cli::safe_exit(1)
        }
        let (_mnemonic, seed) = Wallet::<CliWalletUtils>::gen_hd_seed(
            None,
            &mut OsRng,
            prompt_bip39_passphrase,
        );
        wallet.derive_store_hd_spending_key(
            alias,
            alias_force,
            birthday,
            seed,
            derivation_path,
            password,
        )
    }
    .map(|x| x.0)
    .unwrap_or_else(|| {
        eprintln!("Failed to generate a key.");
        println!("No changes are persisted. Exiting.");
        cli::safe_exit(1);
    });

    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(
        io,
        "Successfully added a spending key with alias: \"{}\"",
        alias
    );
}

/// Generate a shielded payment address from the given key.
fn payment_address_gen(
    ctx: Context,
    io: &impl Io,
    args::PayAddressGen {
        alias,
        alias_force,
        viewing_key: viewing_key_alias,
        diversifier_index,
    }: args::PayAddressGen,
) {
    let mut wallet = load_wallet(ctx);
    let alias = alias.to_lowercase();

    let viewing_key = wallet
        .find_viewing_key(&viewing_key_alias)
        .copied()
        .unwrap_or_else(|_| {
            eprintln!("Unknown viewing key {}", viewing_key_alias,);
            cli::safe_exit(1)
        });
    let diversifier_index = diversifier_index.unwrap_or_else(|| {
        wallet
            .find_diversifier_index(viewing_key_alias.clone())
            .copied()
            .unwrap_or_default()
    });
    let (diversifier_index, masp_payment_addr) =
        ExtendedFullViewingKey::from(viewing_key)
            .find_address(diversifier_index.into())
            .expect("exhausted payment addresses");
    let mut next_div_idx = diversifier_index;
    next_div_idx
        .increment()
        .expect("exhausted payment addresses");
    let payment_addr = PaymentAddress::from(masp_payment_addr);
    let alias = wallet
        .insert_payment_addr(alias, payment_addr, alias_force)
        .unwrap_or_else(|| {
            edisplay_line!(io, "Payment address not added");
            cli::safe_exit(1);
        });
    wallet
        .insert_diversifier_index(viewing_key_alias, next_div_idx.into())
        .expect(
            "must be able to save next diversifier index under the alias of \
             the viewing key",
        );
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    display_line!(
        io,
        "Successfully generated payment address {} at index {} with alias {}",
        payment_addr,
        DiversifierIndex::from(diversifier_index),
        alias,
    );
}

/// Add a viewing key, spending key, or payment address to wallet.
fn shielded_key_address_add(
    ctx: Context,
    io: &impl Io,
    alias: String,
    alias_force: bool,
    birthday: Option<BlockHeight>,
    masp_value: MaspValue,
    unsafe_dont_encrypt: bool,
) {
    let alias = alias.to_lowercase();
    let mut wallet = load_wallet(ctx);
    let (alias, typ) = match masp_value {
        MaspValue::FullViewingKey(viewing_key) => {
            let alias = wallet
                .insert_viewing_key(
                    alias,
                    viewing_key,
                    birthday,
                    alias_force,
                    None,
                )
                .unwrap_or_else(|| {
                    edisplay_line!(io, "Viewing key not added");
                    cli::safe_exit(1);
                });
            (alias, "viewing key")
        }
        MaspValue::ExtendedSpendingKey(spending_key) => {
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            let alias = wallet
                .insert_spending_key(
                    alias,
                    alias_force,
                    spending_key,
                    birthday,
                    password,
                    None,
                )
                .unwrap_or_else(|| {
                    edisplay_line!(io, "Spending key not added");
                    cli::safe_exit(1);
                });
            (alias, "spending key")
        }
        MaspValue::PaymentAddress(payment_addr) => {
            let alias = wallet
                .insert_payment_addr(alias, payment_addr, alias_force)
                .unwrap_or_else(|| {
                    edisplay_line!(io, "Payment address not added");
                    cli::safe_exit(1);
                });
            (alias, "payment address")
        }
    };
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    display_line!(
        io,
        "Successfully added a {} with the following alias to wallet: {}",
        typ,
        alias,
    );
}

/// Decode the derivation path from the given string unless it is "default",
/// in which case use the default derivation path for the given transparent
/// scheme.
pub fn decode_transparent_derivation_path(
    scheme: SchemeType,
    derivation_path: String,
) -> Result<DerivationPath, DerivationPathError> {
    let is_default = derivation_path.eq_ignore_ascii_case("DEFAULT");
    let parsed_derivation_path = if is_default {
        DerivationPath::default_for_transparent_scheme(scheme)
    } else {
        DerivationPath::from_path_string_for_transparent_scheme(
            scheme,
            &derivation_path,
        )?
    };
    Ok(parsed_derivation_path)
}

/// Decode the derivation path from the given string unless it is "default",
/// in which case use the default derivation path for the shielded setting.
pub fn decode_shielded_derivation_path(
    derivation_path: String,
) -> Result<DerivationPath, DerivationPathError> {
    let is_default = derivation_path.eq_ignore_ascii_case("DEFAULT");
    let parsed_derivation_path = if is_default {
        DerivationPath::default_for_shielded()
    } else {
        DerivationPath::from_path_string(&derivation_path)?
    };
    Ok(parsed_derivation_path)
}

/// Derives a keypair and an implicit address from the mnemonic code in the
/// wallet.
async fn transparent_key_and_address_derive(
    ctx: Context,
    io: &impl Io,
    args::KeyDerive {
        scheme,
        alias,
        alias_force,
        unsafe_dont_encrypt,
        derivation_path,
        allow_non_compliant,
        prompt_bip39_passphrase,
        use_device,
        device_transport,
        ..
    }: args::KeyDerive,
) {
    let mut wallet = load_wallet(ctx);
    let derivation_path =
        decode_transparent_derivation_path(scheme, derivation_path)
            .unwrap_or_else(|err| {
                edisplay_line!(io, "{}", err);
                cli::safe_exit(1)
            });
    println!("Using HD derivation path {}", derivation_path);
    if !allow_non_compliant
        && !derivation_path.is_namada_transparent_compliant(scheme)
    {
        display_line!(io, "Path {} is not compliant.", derivation_path);
        display_line!(io, "No changes are persisted. Exiting.");
        cli::safe_exit(1)
    }
    let alias = alias.to_lowercase();
    let alias = if !use_device {
        let (zip32_seed_path, zip32_scheme) = DerivationPath::modified_zip32();
        if scheme == zip32_scheme && derivation_path == zip32_seed_path {
            display_line!(
                io,
                "Path {} is not allowed for safety as it's used in modified \
                 ZIP32 as a seed for deriving shielded keys.",
                zip32_seed_path
            );
            display_line!(io, "No changes are persisted. Exiting.");
            cli::safe_exit(1)
        }
        let encryption_password =
            read_and_confirm_encryption_password(unsafe_dont_encrypt);
        wallet
            .derive_store_key_from_mnemonic_code(
                scheme,
                Some(alias),
                alias_force,
                derivation_path,
                None,
                prompt_bip39_passphrase,
                encryption_password,
            )
            .unwrap_or_else(|| {
                edisplay_line!(io, "Failed to derive a keypair.");
                display_line!(io, "No changes are persisted. Exiting.");
                cli::safe_exit(1)
            })
            .0
    } else {
        let transport = WalletTransport::from_arg(device_transport);
        let app = NamadaApp::new(transport);
        let response = app
            .get_address_and_pubkey(
                &BIP44Path {
                    path: derivation_path.to_string(),
                },
                true,
            )
            .await
            .unwrap_or_else(|err| {
                edisplay_line!(
                    io,
                    "Unable to connect to query address and public key from \
                     Ledger: {}",
                    err
                );
                cli::safe_exit(1)
            });

        let pubkey = common::PublicKey::try_from_slice(&response.public_key)
            .expect("unable to decode public key from hardware wallet");
        let address = Address::from_str(&response.address_str)
            .expect("unable to decode address from hardware wallet");

        wallet
            .insert_public_key(
                alias,
                pubkey,
                Some(address),
                Some(derivation_path),
                alias_force,
            )
            .unwrap_or_else(|| {
                display_line!(io, "No changes are persisted. Exiting.");
                cli::safe_exit(1)
            })
    };
    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(
        io,
        "Successfully added a key and an address with alias: \"{}\"",
        alias
    );
}

/// Generate a new keypair and derive implicit address from it and store them in
/// the wallet.
fn transparent_key_and_address_gen(
    ctx: Context,
    io: &impl Io,
    args::KeyGen {
        scheme,
        raw,
        alias,
        alias_force,
        unsafe_dont_encrypt,
        derivation_path,
        allow_non_compliant,
        prompt_bip39_passphrase,
        ..
    }: args::KeyGen,
) {
    let alias = alias.to_lowercase();
    let mut wallet = load_wallet(ctx);
    let encryption_password =
        read_and_confirm_encryption_password(unsafe_dont_encrypt);
    let alias = if raw {
        wallet.gen_store_secret_key(
            scheme,
            Some(alias),
            alias_force,
            encryption_password,
            &mut OsRng,
        )
    } else {
        let derivation_path =
            decode_transparent_derivation_path(scheme, derivation_path)
                .unwrap_or_else(|err| {
                    edisplay_line!(io, "{}", err);
                    cli::safe_exit(1)
                });
        println!("Using HD derivation path {}", derivation_path);
        if !allow_non_compliant
            && !derivation_path.is_namada_transparent_compliant(scheme)
        {
            display_line!(io, "Path {} is not compliant.", derivation_path);
            display_line!(io, "No changes are persisted. Exiting.");
            cli::safe_exit(1)
        }
        if unsafe_dont_encrypt {
            let (zip32_seed_path, zip32_scheme) =
                DerivationPath::modified_zip32();
            if scheme == zip32_scheme && derivation_path == zip32_seed_path {
                display_line!(
                    io,
                    "Path {} is also used in modified ZIP32 as a seed for \
                     deriving shielded keys. Because you requested to store \
                     this key unencrypted, this may inadvertently expose the \
                     derived shielded key.",
                    zip32_seed_path
                );
            }
        }
        let (_mnemonic, seed) = Wallet::<CliWalletUtils>::gen_hd_seed(
            None,
            &mut OsRng,
            prompt_bip39_passphrase,
        );
        wallet.derive_store_hd_secret_key(
            scheme,
            Some(alias),
            alias_force,
            seed,
            derivation_path,
            encryption_password,
        )
    }
    .map(|x| x.0)
    .unwrap_or_else(|| {
        edisplay_line!(io, "Failed to generate a keypair.");
        println!("No changes are persisted. Exiting.");
        cli::safe_exit(0);
    });
    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(
        io,
        "Successfully added a key and an address with alias: \"{}\"",
        alias
    );
}

/// Key generation
fn key_gen(ctx: Context, io: &impl Io, args_key_gen: args::KeyGen) {
    if !args_key_gen.shielded {
        transparent_key_and_address_gen(ctx, io, args_key_gen)
    } else {
        shielded_key_gen(ctx, io, args_key_gen)
    }
}

/// HD key derivation from mnemonic code
async fn key_derive(
    ctx: Context,
    io: &impl Io,
    args_key_derive: args::KeyDerive,
) {
    if !args_key_derive.shielded {
        transparent_key_and_address_derive(ctx, io, args_key_derive).await
    } else {
        shielded_key_derive(ctx, io, args_key_derive).await
    }
}

/// List keys and addresses
fn key_address_list(
    ctx: Context,
    io: &impl Io,
    args::KeyAddressList {
        decrypt,
        transparent_only,
        shielded_only,
        keys_only,
        addresses_only,
        unsafe_show_secret,
    }: args::KeyAddressList,
) {
    let wallet = load_wallet(ctx);
    if !shielded_only {
        if !addresses_only {
            transparent_keys_list(
                &wallet,
                io,
                decrypt,
                unsafe_show_secret,
                transparent_only && keys_only,
            )
        }
        if !keys_only {
            transparent_addresses_list(
                &wallet,
                io,
                transparent_only && addresses_only,
            )
        }
    }

    if !transparent_only {
        if !addresses_only {
            shielded_keys_list(
                &wallet,
                io,
                decrypt,
                unsafe_show_secret,
                shielded_only && keys_only,
            )
        }
        if !keys_only {
            payment_addresses_list(&wallet, io, shielded_only && addresses_only)
        }
    }
}

/// Find keys and addresses
fn key_address_find(
    ctx: Context,
    io: &impl Io,
    args::KeyAddressFind {
        alias,
        address,
        public_key,
        public_key_hash,
        payment_address,
        keys_only,
        addresses_only,
        decrypt,
        unsafe_show_secret,
    }: args::KeyAddressFind,
) {
    if let Some(alias) = alias {
        // Search keys and addresses by alias
        let mut wallet = load_wallet(ctx);
        let found_transparent = transparent_key_address_find_by_alias(
            &mut wallet,
            io,
            alias.clone(),
            keys_only,
            addresses_only,
            decrypt,
            unsafe_show_secret,
        );
        let found_shielded = shielded_key_address_find_by_alias(
            &mut wallet,
            io,
            alias.clone(),
            keys_only,
            addresses_only,
            decrypt,
            unsafe_show_secret,
        );
        if !found_transparent && !found_shielded {
            display_line!(io, "Alias \"{}\" not found.", alias);
        }
    } else if address.is_some() {
        // Search alias by address
        transparent_address_or_alias_find(ctx, io, None, address)
    } else if public_key.is_some() || public_key_hash.is_some() {
        // Search transparent keypair by public key or public key hash
        transparent_key_find(
            ctx,
            io,
            None,
            public_key,
            public_key_hash,
            unsafe_show_secret,
        )
    } else if payment_address.is_some() {
        // Search alias by MASP payment address
        payment_address_or_alias_find(ctx, io, None, payment_address)
    }
}

#[derive(Debug)]
pub enum TransparentValue {
    /// Transparent secret key
    TranspSecretKey(common::SecretKey),
    /// Transparent public key
    TranspPublicKey(common::PublicKey),
    /// Transparent address
    TranspAddress(Address),
}

impl FromStr for TransparentValue {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try to decode this value first as a secret key, then as a public key,
        // then as an address
        common::SecretKey::from_str(s)
            .map(Self::TranspSecretKey)
            .or_else(|_| {
                common::PublicKey::from_str(s).map(Self::TranspPublicKey)
            })
            .or_else(|_| Address::from_str(s).map(Self::TranspAddress))
    }
}

/// Value for wallet `add` command
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum KeyAddrAddValue {
    /// Transparent value
    TranspValue(TransparentValue),
    /// Masp value
    MASPValue(MaspValue),
}

impl FromStr for KeyAddrAddValue {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try to decode this value first as a transparent value, then as a MASP
        // value
        TransparentValue::from_str(s)
            .map(Self::TranspValue)
            .or_else(|_| MaspValue::from_str(s).map(Self::MASPValue))
    }
}

fn add_key_or_address(
    ctx: Context,
    io: &impl Io,
    alias: String,
    alias_force: bool,
    birthday: Option<BlockHeight>,
    value: KeyAddrAddValue,
    unsafe_dont_encrypt: bool,
) {
    match value {
        KeyAddrAddValue::TranspValue(TransparentValue::TranspSecretKey(sk)) => {
            transparent_secret_key_add(
                ctx,
                io,
                alias,
                alias_force,
                sk,
                unsafe_dont_encrypt,
            )
        }
        KeyAddrAddValue::TranspValue(TransparentValue::TranspPublicKey(
            pubkey,
        )) => transparent_public_key_add(ctx, io, alias, alias_force, pubkey),
        KeyAddrAddValue::TranspValue(TransparentValue::TranspAddress(
            address,
        )) => transparent_address_add(ctx, io, alias, alias_force, address),
        KeyAddrAddValue::MASPValue(masp_value) => shielded_key_address_add(
            ctx,
            io,
            alias,
            alias_force,
            birthday,
            masp_value,
            unsafe_dont_encrypt,
        ),
    }
}

/// Add key or address
fn key_address_add(
    ctx: Context,
    io: &impl Io,
    args::KeyAddressAdd {
        alias,
        alias_force,
        value,
        birthday,
        unsafe_dont_encrypt,
    }: args::KeyAddressAdd,
) {
    let value = KeyAddrAddValue::from_str(&value).unwrap_or_else(|err| {
        edisplay_line!(io, "{}", err);
        display_line!(io, "No changes are persisted. Exiting.");
        cli::safe_exit(1)
    });
    add_key_or_address(
        ctx,
        io,
        alias,
        alias_force,
        birthday,
        value,
        unsafe_dont_encrypt,
    )
}

/// Remove keys and addresses
fn key_address_remove(
    ctx: Context,
    io: &impl Io,
    args::KeyAddressRemove { alias, .. }: args::KeyAddressRemove,
) {
    let alias = alias.to_lowercase();
    let mut wallet = load_wallet(ctx);
    wallet.remove_all_by_alias(alias.clone());
    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(io, "Successfully removed alias: \"{}\"", alias);
}

/// Find a keypair in the wallet store.
fn transparent_key_find(
    ctx: Context,
    io: &impl Io,
    alias: Option<String>,
    public_key: Option<common::PublicKey>,
    public_key_hash: Option<String>,
    unsafe_show_secret: bool,
) {
    let mut wallet = load_wallet(ctx);
    let found_keypair = match public_key {
        Some(pk) => wallet.find_key_by_pk(&pk, None),
        None => {
            let alias = alias.map(|a| a.to_lowercase()).or(public_key_hash);
            match alias {
                None => {
                    edisplay_line!(
                        io,
                        "An alias, public key or public key hash needs to be \
                         supplied",
                    );
                    cli::safe_exit(1)
                }
                Some(alias) => wallet.find_secret_key(alias, None),
            }
        }
    };
    match found_keypair {
        Ok(keypair) => {
            let pkh: PublicKeyHash = (&keypair.ref_to()).into();
            display_line!(io, "Public key hash: {}", pkh);
            display_line!(io, "Public key: {}", keypair.ref_to());
            if unsafe_show_secret {
                display_line!(io, "Secret key: {}", keypair);
            }
        }
        Err(err) => {
            edisplay_line!(io, "{}", err);
        }
    }
}

/// Find address (alias) by its alias (address).
fn transparent_address_or_alias_find(
    ctx: Context,
    io: &impl Io,
    alias: Option<String>,
    address: Option<Address>,
) {
    let wallet = load_wallet(ctx);
    if address.is_some() && alias.is_some() {
        panic!(
            "This should not be happening: clap should emit its own error \
             message."
        );
    } else if alias.is_some() {
        let alias = alias.unwrap().to_lowercase();
        if let Some(address) = wallet.find_address(&alias) {
            display_line!(io, "Found address {}", address.to_pretty_string());
        } else {
            display_line!(
                io,
                "No address with alias {} found. Use the command `list \
                 --addr` to see all the known transparent addresses.",
                alias
            );
        }
    } else if let Some(address) = address.as_ref() {
        if let Some(alias) = wallet.find_alias(address) {
            display_line!(io, "Found alias {}", alias);
        } else {
            display_line!(
                io,
                "No address with alias {} found. Use the command `list \
                 --addr` to see all the known transparent addresses.",
                address
            );
        }
    }
}

/// Find payment address (alias) by its alias (payment address).
fn payment_address_or_alias_find(
    ctx: Context,
    io: &impl Io,
    alias: Option<String>,
    payment_address: Option<PaymentAddress>,
) {
    let wallet = load_wallet(ctx);
    if payment_address.is_some() && alias.is_some() {
        panic!(
            "This should not be happening: clap should emit its own error \
             message."
        );
    } else if alias.is_some() {
        let alias = alias.unwrap().to_lowercase();
        if let Some(payment_addr) = wallet.find_payment_addr(&alias) {
            display_line!(io, "Found payment address {}", payment_addr);
        } else {
            display_line!(
                io,
                "No payment address with alias {} found. Use the command \
                 `list --shielded --addr` to see all the known payment \
                 addresses.",
                alias
            );
        }
    } else if let Some(address) = payment_address.as_ref() {
        if let Some(alias) = wallet.find_alias_by_payment_addr(address) {
            display_line!(io, "Found alias {}", alias);
        } else {
            display_line!(
                io,
                "No address with alias {} found. Use the command `list \
                 --shielded --addr` to see all the known payment addresses.",
                address
            );
        }
    }
}

/// Find transparent addresses and keys by alias
fn transparent_key_address_find_by_alias(
    wallet: &mut Wallet<CliWalletUtils>,
    io: &impl Io,
    alias: String,
    keys_only: bool,
    addresses_only: bool,
    decrypt: bool,
    unsafe_show_secret: bool,
) -> bool {
    let alias = alias.to_lowercase();
    let mut w_lock = io::stdout().lock();
    let mut found = false;

    // Find transparent keys
    if !addresses_only {
        // Check if alias is a public key
        if let Ok(public_key) = wallet.find_public_key(&alias) {
            found = true;
            display_line!(io, &mut w_lock; "Found transparent keys:").unwrap();
            let encrypted = match wallet.is_encrypted_secret_key(&alias) {
                None => "external",
                Some(res) if res => "encrypted",
                _ => "not encrypted",
            };
            display_line!(io,
                &mut w_lock;
                "  Alias \"{}\" ({}):", alias, encrypted,
            )
            .unwrap();
            let pkh = PublicKeyHash::from(&public_key);
            // Always print the public key and hash
            display_line!(io, &mut w_lock; "    Public key hash: {}", pkh)
                .unwrap();
            display_line!(
                io,
                &mut w_lock;
                "    Public key: {}",
                public_key
            )
            .unwrap();
            if decrypt {
                // Check if alias is also a secret key. Decrypt and print it if
                // requested.
                match wallet.find_secret_key(&alias, None) {
                    Ok(keypair) => {
                        if unsafe_show_secret {
                            display_line!(io, &mut w_lock; "    Secret key: {}", keypair) .unwrap();
                        }
                    }
                    Err(FindKeyError::KeyDecryptionError(
                        DecryptionError::EmptyPassword,
                    )) => {
                        display_line!(io,
                                      &mut w_lock;
                                      "Decryption of the keypair cancelled: no password provided"
                        )
                        .unwrap();
                    }
                    Err(FindKeyError::KeyNotFound(_)) => {}
                    Err(err) => edisplay_line!(io, "{}", err),
                }
            }
        }
    }

    // Find transparent address
    if !keys_only {
        if let Some(address) = wallet.find_address(&alias) {
            found = true;
            display_line!(io, &mut w_lock; "Found transparent address:")
                .unwrap();
            display_line!(io,
                &mut w_lock;
                "  \"{}\": {}", alias, address.to_pretty_string(),
            )
            .unwrap();
        }
    }

    found
}

/// Find shielded payment address and keys by alias
fn shielded_key_address_find_by_alias(
    wallet: &mut Wallet<CliWalletUtils>,
    io: &impl Io,
    alias: String,
    keys_only: bool,
    addresses_only: bool,
    decrypt: bool,
    unsafe_show_secret: bool,
) -> bool {
    let alias = alias.to_lowercase();
    let mut w_lock = io::stdout().lock();
    let mut found = false;

    // Find shielded keys
    if !addresses_only {
        let encrypted = match wallet.is_encrypted_spending_key(&alias) {
            None => "external",
            Some(res) if res => "encrypted",
            _ => "not encrypted",
        };
        // Check if alias is a viewing key
        if let Ok(viewing_key) = wallet.find_viewing_key(&alias) {
            found = true;
            display_line!(io, &mut w_lock; "Found shielded keys:").unwrap();
            display_line!(io,
                &mut w_lock;
                "  Alias \"{}\" ({}):", alias, encrypted,
            )
            .unwrap();
            // Always print the viewing key
            display_line!(io, &mut w_lock; "    Viewing key: {}", viewing_key)
                .unwrap();
            if decrypt {
                // Check if alias is also a spending key. Decrypt and print it
                // if requested.
                match wallet.find_spending_key(&alias, None) {
                    Ok(spending_key) => {
                        if unsafe_show_secret {
                            display_line!(io, &mut w_lock; "    Spending key: {}", spending_key).unwrap();
                        }
                    }
                    Err(FindKeyError::KeyDecryptionError(
                        DecryptionError::EmptyPassword,
                    )) => {
                        display_line!(io,
                                      &mut w_lock;
                                      "Decryption of the shielded key cancelled: no password provided"
                        )
                        .unwrap();
                    }
                    Err(FindKeyError::KeyNotFound(_)) => {}
                    Err(err) => edisplay_line!(io, "{}", err),
                }
            }
        }
    }

    // Find payment addresses
    if !keys_only {
        if let Some(payment_addr) = wallet.find_payment_addr(&alias) {
            found = true;
            display_line!(io, &mut w_lock; "Found payment address:").unwrap();
            display_line!(io,
                &mut w_lock;
                "  \"{}\": {}", alias, payment_addr.to_string(),
            )
            .unwrap();
        }
    }

    found
}

/// List all known keys.
fn transparent_keys_list(
    wallet: &Wallet<CliWalletUtils>,
    io: &impl Io,
    decrypt: bool,
    unsafe_show_secret: bool,
    show_hint: bool,
) {
    let known_public_keys = wallet.get_public_keys();
    if known_public_keys.is_empty() {
        if show_hint {
            display_line!(
                io,
                "No known keys. Try `gen --alias my-key` to generate a new \
                 key.",
            );
        }
    } else {
        let mut w_lock = io::stdout().lock();
        display_line!(io, &mut w_lock; "Known transparent keys:").unwrap();
        let known_secret_keys = wallet.get_secret_keys();
        for (alias, public_key) in known_public_keys {
            let stored_keypair = known_secret_keys.get(&alias);
            let encrypted = match stored_keypair {
                None => "external",
                Some((stored_keypair, _pkh))
                    if stored_keypair.is_encrypted() =>
                {
                    "encrypted"
                }
                Some(_) => "not encrypted",
            };
            display_line!(io,
                &mut w_lock;
                "  Alias \"{}\" ({}):", alias, encrypted,
            )
            .unwrap();
            // Always print the corresponding public key and hash
            display_line!(io, &mut w_lock; "    Public key hash: {}", PublicKeyHash::from(&public_key))
                .unwrap();
            display_line!(io, &mut w_lock; "    Public key: {}", public_key)
                .unwrap();
            // A subset of public keys will have corresponding secret keys.
            // Print those too if they are available and requested.
            if let Some((stored_keypair, _pkh)) = stored_keypair {
                match stored_keypair.get::<CliWalletUtils>(
                    decrypt,
                    None,
                    Some(&alias),
                ) {
                    Ok(keypair) => {
                        if unsafe_show_secret {
                            display_line!(io,
                                          &mut w_lock;
                                          "    Secret key: {}", keypair,
                            )
                            .unwrap();
                        }
                    }
                    Err(DecryptionError::EmptyPassword) => {
                        display_line!(io,
                                      &mut w_lock;
                                      "Decryption of the keypair cancelled: no password provided"
                        )
                        .unwrap();
                    }
                    Err(DecryptionError::NotDecrypting) if !decrypt => {
                        continue;
                    }
                    Err(err) => {
                        display_line!(io,
                                      &mut w_lock;
                                      "    Couldn't decrypt the keypair: {}", err,
                        )
                            .unwrap();
                    }
                }
            }
        }
    }
}

/// Export a transparent keypair / MASP spending key to a file.
fn key_export(
    ctx: Context,
    io: &impl Io,
    args::KeyExport { alias }: args::KeyExport,
) {
    let alias = alias.to_lowercase();
    let mut wallet = load_wallet(ctx);
    let key_to_export = wallet
        .find_secret_key(&alias, None)
        .map(|sk| Box::new(sk) as Box<dyn BorshSerializeExt>)
        .or(wallet
            .find_spending_key(&alias, None)
            .map(|spk| Box::new(spk) as Box<dyn BorshSerializeExt>));
    key_to_export
        .map(|key| {
            let file_data = key.serialize_to_vec();
            let file_name = format!("key_{}", alias);
            let mut file = File::create(&file_name).unwrap();
            file.write_all(file_data.as_ref()).unwrap();
            display_line!(io, "Exported to file {}", file_name);
        })
        .unwrap_or_else(|err| {
            edisplay_line!(io, "{}", err);
            cli::safe_exit(1)
        })
}

/// Convert a consensus key to tendermint validator key in json format
fn key_convert(
    ctx: Context,
    io: &impl Io,
    args::KeyConvert { alias }: args::KeyConvert,
) {
    let alias = alias.to_lowercase();
    let mut wallet = load_wallet(ctx);
    let sk = wallet.find_secret_key(&alias, None);
    let key: serde_json::Value = validator_key_to_json(&sk.unwrap()).unwrap();
    let file_name = format!("priv_validator_key_{}.json", alias);
    let file = File::create(&file_name).unwrap();
    serde_json::to_writer_pretty(file, &key).unwrap_or_else(|err| {
        edisplay_line!(io, "{}", err);
        cli::safe_exit(1)
    });
    display_line!(io, "Converted to file {}", file_name);
}

/// Import a transparent keypair / MASP spending key from a file.
fn key_import(
    ctx: Context,
    io: &impl Io,
    args::KeyImport {
        file_path,
        alias,
        alias_force,
        unsafe_dont_encrypt,
    }: args::KeyImport,
) {
    let file_data = std::fs::read(file_path).unwrap_or_else(|err| {
        edisplay_line!(io, "{}", err);
        display_line!(io, "No changes are persisted. Exiting.");
        cli::safe_exit(1)
    });
    if let Ok(sk) = common::SecretKey::try_from_slice(&file_data) {
        transparent_secret_key_add(
            ctx,
            io,
            alias,
            alias_force,
            sk,
            unsafe_dont_encrypt,
        );
    } else if let Ok(spend_key) =
        ExtendedSpendingKey::try_from_slice(&file_data)
    {
        let masp_value = MaspValue::ExtendedSpendingKey(spend_key);
        shielded_key_address_add(
            ctx,
            io,
            alias,
            alias_force,
            None,
            masp_value,
            unsafe_dont_encrypt,
        );
    } else {
        display_line!(io, "Could not parse the data.");
        display_line!(io, "No changes are persisted. Exiting.");
        cli::safe_exit(1)
    }
}

/// List all known transparent addresses.
fn transparent_addresses_list(
    wallet: &Wallet<CliWalletUtils>,
    io: &impl Io,
    show_hint: bool,
) {
    let known_addresses = wallet.get_addresses();
    if known_addresses.is_empty() {
        if show_hint {
            display_line!(
                io,
                "No known addresses. Try `gen --alias my-addr` to generate a \
                 new implicit address.",
            );
        }
    } else {
        let mut w_lock = io::stdout().lock();
        display_line!(io, &mut w_lock; "Known transparent addresses:").unwrap();
        for (alias, address) in sorted(known_addresses) {
            display_line!(io,
                &mut w_lock;
                "  \"{}\": {}", alias, address.to_pretty_string(),
            )
            .unwrap();
        }
    }
}

/// Add a transparent secret key to the wallet.
fn transparent_secret_key_add(
    ctx: Context,
    io: &impl Io,
    alias: String,
    alias_force: bool,
    sk: common::SecretKey,
    unsafe_dont_encrypt: bool,
) {
    let mut wallet = load_wallet(ctx);
    let encryption_password =
        read_and_confirm_encryption_password(unsafe_dont_encrypt);
    let alias = wallet
        .insert_keypair(alias, alias_force, sk, encryption_password, None, None)
        .unwrap_or_else(|| {
            edisplay_line!(io, "Failed to add a keypair.");
            display_line!(io, "No changes are persisted. Exiting.");
            cli::safe_exit(1);
        });
    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(
        io,
        "Successfully added a key and an address with alias: \"{}\"",
        alias
    );
}

/// Add a public key to the wallet.
fn transparent_public_key_add(
    ctx: Context,
    io: &impl Io,
    alias: String,
    alias_force: bool,
    pubkey: common::PublicKey,
) {
    let alias = alias.to_lowercase();
    let mut wallet = load_wallet(ctx);
    if wallet
        .insert_public_key(alias.clone(), pubkey, None, None, alias_force)
        .is_none()
    {
        edisplay_line!(io, "Public key not added");
        cli::safe_exit(1);
    }
    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(
        io,
        "Successfully added a public key with alias: \"{}\"",
        alias
    );
}

/// Add a transparent address to the wallet.
fn transparent_address_add(
    ctx: Context,
    io: &impl Io,
    alias: String,
    alias_force: bool,
    address: Address,
) {
    let alias = alias.to_lowercase();
    let mut wallet = load_wallet(ctx);
    if wallet
        .insert_address(&alias, address, alias_force)
        .is_none()
    {
        edisplay_line!(io, "Address not added");
        cli::safe_exit(1);
    }
    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(
        io,
        "Successfully added an address with alias: \"{}\"",
        alias
    );
}

/// Load wallet for chain when `ctx.chain.is_some()` or pre-genesis wallet when
/// `ctx.global_args.is_pre_genesis`.
fn load_wallet(ctx: Context) -> Wallet<CliWalletUtils> {
    if ctx.global_args.is_pre_genesis {
        let wallet_path = ctx.global_args.base_dir.join(PRE_GENESIS_DIR);
        wallet::load_or_new(&wallet_path)
    } else {
        ctx.take_chain_or_exit().wallet
    }
}
