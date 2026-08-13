use std::collections::BTreeMap;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::convert::AllowedConversion;
use masp_primitives::ff::PrimeField;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::I128Sum;
use namada_core::borsh::BorshSerializeExt;
use namada_core::chain::BlockHeight;
use namada_core::dec::Dec;
use namada_core::hash::Hash;
use namada_core::masp::{Precision, encode_asset_type};
use namada_core::storage::Key;
use namada_core::time::MIN_UTC;
use namada_macros::BorshDeserializer;
use namada_migrations::REGISTER_DESERIALIZERS;
use namada_parameters::EpochDuration;
use namada_parameters::storage::{
    get_epoch_duration_storage_key, get_epochs_per_year_key,
    get_masp_epoch_multiplier_key, get_tx_allowlist_storage_key,
};
use namada_sdk::address::Address;
use namada_sdk::ibc::trace::ibc_token;
use namada_sdk::masp_primitives::asset_type::AssetType;
use namada_sdk::masp_primitives::merkle_tree::FrozenCommitmentTree;
use namada_sdk::masp_primitives::sapling;
use namada_sdk::migrations;
use namada_sdk::storage::DbColFam;
use namada_shielded_token::storage_key::{
    masp_assets_hash_key, masp_conversion_key, masp_kd_gain_key,
    masp_kp_gain_key, masp_locked_amount_target_key, masp_max_reward_rate_key,
    masp_reward_precision_key, masp_scheduled_base_native_precision_key,
    masp_scheduled_reward_precision_key,
};
use namada_shielded_token::{ConversionLeaf, ConversionState, MaspEpoch};
use namada_trans_token::storage_key::{balance_key, minted_balance_key};
use namada_trans_token::{Amount, Denomination, MaspDigitPos, Store};
use sha2::{Digest, Sha256};

/// Represents the channel ID of an IBC token
pub type ChannelId = &'static str;
/// Represents the base token of an IBC token
pub type BaseToken = &'static str;
/// Represents a Namada address in Bech32m encoding
pub type AddressBech32m = &'static str;
/// Represents the hash of a WASM binary
pub type WasmHash = &'static str;
/// Represents the bytes of a WASM binary
pub type WasmBytes = &'static [u8];
/// Represents a maximum reward rate
pub type MaxRewardRate = &'static str;
/// Represents a target locked amount
pub type TargetLockedAmount = u64;
/// Represents a nominal proportional gain
pub type KpGain = &'static str;
/// Represents a nominal derivative gain
pub type KdGain = &'static str;
/// The type hash of the conversion state structure in v0.31.9
pub const OLD_CONVERSION_STATE_TYPE_HASH: &str =
    "05E2FD0BEBD54A05AAE349BBDE61F90893F09A72850EFD4F69060821EC5DE65F";

/// The new conversion state structure after the v0.32.0 upgrade
#[derive(
    Debug, Default, BorshSerialize, BorshDeserialize, BorshDeserializer,
)]
pub struct NewConversionState {
    /// The last amount of the native token distributed
    pub current_precision: Option<u128>,
    /// The tree currently containing all the conversions
    pub tree: FrozenCommitmentTree<sapling::Node>,
    /// Map assets to their latest conversion and position in Merkle tree
    #[allow(clippy::type_complexity)]
    pub assets: BTreeMap<AssetType, ConversionLeaf>,
}

impl From<ConversionState> for NewConversionState {
    fn from(value: ConversionState) -> Self {
        Self {
            #[allow(deprecated)]
            current_precision: value.current_precision,
            tree: value.tree,
            assets: value.assets,
        }
    }
}

/// Demonstrate how to set the minted balance using a migration
pub fn minted_balance_migration(updates: &mut Vec<migrations::DbUpdateType>) {
    let person =
        Address::decode("tnam1q9rhgyv3ydq0zu3whnftvllqnvhvhm270qxay5tn")
            .unwrap();
    let nam = Address::decode("tnam1qxgfw7myv4dh0qna4hq0xdg6lx77fzl7dcem8h7e")
        .unwrap();
    let apfel = "tnam1qyvfwdkz8zgs9n3qn9xhp8scyf8crrxwuq26r6gy".to_string();
    let amount = Amount::native_whole(3200000036910u64);
    let minted_key = minted_balance_key(&nam);
    let minted_value = Amount::from(117600000504441u64);

    updates.push(migrations::DbUpdateType::Add {
        key: balance_key(&nam, &person),
        cf: DbColFam::SUBSPACE,
        value: amount.into(),
        force: false,
    });
    updates.push(migrations::DbUpdateType::Add {
        key: minted_key,
        cf: DbColFam::SUBSPACE,
        value: minted_value.into(),
        force: false,
    });
    updates.push(migrations::DbUpdateType::RepeatDelete(
        apfel,
        DbColFam::SUBSPACE,
    ));
}

/// A convenience data structure to allow token addresses to be more readably
/// expressed as a channel ID and base token instead of a raw Namada address.
pub enum TokenAddress {
    // Specify an IBC address. This can also be done more directly using the
    // Self::Address variant.
    Ibc(ChannelId, BaseToken),
    // Directly specify a Namada address
    Address(AddressBech32m),
}

/// Demonstrate how to set the shielded reward precision of IBC tokens using a
/// migration
pub fn shielded_reward_precision_migration(
    updates: &mut Vec<migrations::DbUpdateType>,
) {
    const TOKENS: [(TokenAddress, Precision); 6] = [
        (TokenAddress::Ibc("channel-1", "uosmo"), 1000u128),
        (TokenAddress::Ibc("channel-2", "uatom"), 1000u128),
        (TokenAddress::Ibc("channel-3", "utia"), 1000u128),
        (TokenAddress::Ibc("channel-0", "stuosmo"), 1000u128),
        (TokenAddress::Ibc("channel-0", "stuatom"), 1000u128),
        (TokenAddress::Ibc("channel-0", "stutia"), 1000u128),
    ];

    // Set IBC token shielded reward precisions
    for (token_address, precision) in TOKENS {
        // Compute the Namada address
        let token_address = match token_address {
            TokenAddress::Ibc(channel_id, base_token) => {
                let ibc_denom = format!("transfer/{channel_id}/{base_token}");
                ibc_token(&ibc_denom).clone()
            }
            TokenAddress::Address(addr) => Address::from_str(addr)
                .expect("unable to construct token address"),
        };

        // The key holding the shielded reward precision of current token
        let shielded_token_reward_precision_key =
            masp_reward_precision_key::<Store<()>>(&token_address);

        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_reward_precision_key,
            cf: DbColFam::SUBSPACE,
            value: precision.into(),
            force: false,
        });
    }
}

/// Demonstrate clearing MASP rewards for the given IBC tokens by overwriting
/// their allowed conversions with conversions that do not contain rewards.
pub fn shielded_reward_reset_migration(
    updates: &mut Vec<migrations::DbUpdateType>,
) {
    // The address of the native token. This is what rewards are denominated in.
    const NATIVE_TOKEN_BECH32M: AddressBech32m =
        "tnam1qxgfw7myv4dh0qna4hq0xdg6lx77fzl7dcem8h7e";
    let native_token = Address::from_str(NATIVE_TOKEN_BECH32M)
        .expect("unable to construct native token address");
    // The MASP epoch in which this migration will be applied. This number
    // controls the number of epochs of conversions created.
    const TARGET_MASP_EPOCH: MaspEpoch = MaspEpoch::new(2000);
    // The tokens whose rewarrds will be reset.
    const TOKENS: [(TokenAddress, Denomination, Precision); 6] = [
        (
            TokenAddress::Ibc("channel-1", "uosmo"),
            Denomination(0u8),
            1000u128,
        ),
        (
            TokenAddress::Ibc("channel-2", "uatom"),
            Denomination(0u8),
            1000u128,
        ),
        (
            TokenAddress::Ibc("channel-3", "utia"),
            Denomination(0u8),
            1000u128,
        ),
        (
            TokenAddress::Ibc("channel-0", "stuosmo"),
            Denomination(0u8),
            1000u128,
        ),
        (
            TokenAddress::Ibc("channel-0", "stuatom"),
            Denomination(0u8),
            1000u128,
        ),
        (
            TokenAddress::Ibc("channel-0", "stutia"),
            Denomination(0u8),
            1000u128,
        ),
    ];

    // Reset the allowed conversions for the above tokens
    for (token_address, denomination, precision) in TOKENS {
        // Compute the Namada address
        let token_address = match token_address {
            TokenAddress::Ibc(channel_id, base_token) => {
                let ibc_denom = format!("transfer/{channel_id}/{base_token}");
                ibc_token(&ibc_denom).clone()
            }
            TokenAddress::Address(addr) => Address::from_str(addr)
                .expect("unable to construct token address"),
        };
        // Erase the TOK rewards that have been distributed so far
        let mut asset_types = BTreeMap::new();
        let mut precision_toks = BTreeMap::new();
        let mut reward_deltas = BTreeMap::new();
        // TOK[ep, digit]
        let mut asset_type = |epoch, digit| {
            *asset_types.entry((epoch, digit)).or_insert_with(|| {
                encode_asset_type(
                    token_address.clone(),
                    denomination,
                    digit,
                    Some(epoch),
                )
                .expect("unable to encode asset type")
            })
        };
        // PRECISION TOK[ep, digit]
        let mut precision_tok = |epoch, digit| {
            precision_toks
                .entry((epoch, digit))
                .or_insert_with(|| {
                    AllowedConversion::from(I128Sum::from_pair(
                        asset_type(epoch, digit),
                        i128::try_from(precision).expect("precision too large"),
                    ))
                })
                .clone()
        };
        // -PRECISION TOK[ep, digit] + PRECISION TOK[ep+1, digit]
        let mut reward_delta = |epoch, digit| {
            reward_deltas
                .entry((epoch, digit))
                .or_insert_with(|| {
                    -precision_tok(epoch, digit)
                        + precision_tok(epoch.next().unwrap(), digit)
                })
                .clone()
        };
        // The key holding the shielded reward precision of current token
        let shielded_token_reward_precision_key =
            masp_scheduled_reward_precision_key(
                &TARGET_MASP_EPOCH,
                &token_address,
            );

        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_reward_precision_key,
            cf: DbColFam::SUBSPACE,
            value: precision.into(),
            force: false,
        });
        // If the current token is the native token, then also update the base
        // native precision
        if token_address == native_token {
            let shielded_token_base_native_precision_key =
                masp_scheduled_base_native_precision_key(&TARGET_MASP_EPOCH);

            updates.push(migrations::DbUpdateType::Add {
                key: shielded_token_base_native_precision_key,
                cf: DbColFam::SUBSPACE,
                value: precision.into(),
                force: false,
            });
        }
        // Write the new TOK conversions to memory
        for digit in MaspDigitPos::iter() {
            // -PRECISION TOK[ep, digit] + PRECISION TOK[current_ep, digit]
            let mut reward: AllowedConversion = I128Sum::zero().into();
            for epoch in MaspEpoch::iter_bounds_inclusive(
                MaspEpoch::zero(),
                TARGET_MASP_EPOCH.prev().unwrap(),
            )
            .rev()
            {
                // TOK[ep, digit]
                let asset_type = encode_asset_type(
                    token_address.clone(),
                    denomination,
                    digit,
                    Some(epoch),
                )
                .expect("unable to encode asset type");
                reward += reward_delta(epoch, digit);
                // Write the conversion update to memory
                updates.push(migrations::DbUpdateType::Add {
                    key: masp_conversion_key(&TARGET_MASP_EPOCH, &asset_type),
                    cf: DbColFam::SUBSPACE,
                    value: reward.clone().into(),
                    force: false,
                });
            }
        }
    }
}

/// Demonstrate replacing the entire conversion state with a new state that does
/// not contain rewards.
pub fn conversion_state_migration(updates: &mut Vec<migrations::DbUpdateType>) {
    // The MASP epoch in which this migration will be applied. This number
    // controls the number of epochs of conversions created.
    const TARGET_MASP_EPOCH: MaspEpoch = MaspEpoch::new(4);
    // Precision to use for the native token
    const NATIVE_PRECISION: Precision = 1000;
    // The tokens whose rewarrds will be reset.
    const TOKENS: [(TokenAddress, Denomination, Precision); 7] = [
        (
            TokenAddress::Address(
                "tnam1qyvfwdkz8zgs9n3qn9xhp8scyf8crrxwuq26r6gy",
            ),
            Denomination(6),
            1000u128,
        ),
        (
            TokenAddress::Address(
                "tnam1qy8qgxlcteehlk70sn8wx2pdlavtayp38vvrnkhq",
            ),
            Denomination(8),
            10000u128,
        ),
        (
            TokenAddress::Address(
                "tnam1qyfl072lhaazfj05m7ydz8cr57zdygk375jxjfwx",
            ),
            Denomination(10),
            10000000u128,
        ),
        (
            TokenAddress::Address(
                "tnam1qxvnvm2t9xpceu8rup0n6espxyj2ke36yv4dw6q5",
            ),
            Denomination(18),
            10000u128,
        ),
        (
            TokenAddress::Address(
                "tnam1qyx93z5ma43jjmvl0xhwz4rzn05t697f3vfv8yuj",
            ),
            Denomination(6),
            1000u128,
        ),
        (
            TokenAddress::Address(
                "tnam1qxgfw7myv4dh0qna4hq0xdg6lx77fzl7dcem8h7e",
            ),
            Denomination(6),
            NATIVE_PRECISION,
        ),
        (
            TokenAddress::Address(
                "tnam1q9f5yynt5qfxe28ae78xxp7wcgj50fn4syetyrj6",
            ),
            Denomination(6),
            1000u128,
        ),
    ];

    let mut assets = BTreeMap::new();
    let mut conv_notes = Vec::new();
    // Reset the allowed conversions for the above tokens
    for (token_address, denomination, precision) in TOKENS {
        // Compute the Namada address
        let token_address = match token_address {
            TokenAddress::Ibc(channel_id, base_token) => {
                let ibc_denom = format!("transfer/{channel_id}/{base_token}");
                ibc_token(&ibc_denom).clone()
            }
            TokenAddress::Address(addr) => Address::from_str(addr)
                .expect("unable to construct token address"),
        };
        // Erase the TOK rewards that have been distributed so far
        let mut asset_types = BTreeMap::new();
        let mut precision_toks = BTreeMap::new();
        let mut reward_deltas = BTreeMap::new();
        // TOK[ep, digit]
        let mut asset_type = |epoch, digit| {
            *asset_types.entry((epoch, digit)).or_insert_with(|| {
                encode_asset_type(
                    token_address.clone(),
                    denomination,
                    digit,
                    Some(epoch),
                )
                .expect("unable to encode asset type")
            })
        };
        // PRECISION TOK[ep, digit]
        let mut precision_tok = |epoch, digit| {
            precision_toks
                .entry((epoch, digit))
                .or_insert_with(|| {
                    AllowedConversion::from(I128Sum::from_pair(
                        asset_type(epoch, digit),
                        precision.try_into().expect("precision too large"),
                    ))
                })
                .clone()
        };
        // -PRECISION TOK[ep, digit] + PRECISION TOK[ep+1, digit]
        let mut reward_delta = |epoch, digit| {
            reward_deltas
                .entry((epoch, digit))
                .or_insert_with(|| {
                    -precision_tok(epoch, digit)
                        + precision_tok(epoch.next().unwrap(), digit)
                })
                .clone()
        };
        // The key holding the shielded reward precision of current token
        let shielded_token_reward_precision_key =
            masp_reward_precision_key::<Store<()>>(&token_address);

        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_reward_precision_key,
            cf: DbColFam::SUBSPACE,
            value: precision.into(),
            force: false,
        });
        // Build up the new TOK conversions into an object
        for digit in MaspDigitPos::iter() {
            // -PRECISION TOK[ep, digit] + PRECISION TOK[current_ep, digit]
            let mut reward: AllowedConversion = I128Sum::zero().into();
            for epoch in MaspEpoch::iter_bounds_inclusive(
                MaspEpoch::zero(),
                TARGET_MASP_EPOCH,
            )
            .rev()
            {
                // TOK[ep, digit]
                let asset_type = encode_asset_type(
                    token_address.clone(),
                    denomination,
                    digit,
                    Some(epoch),
                )
                .expect("unable to encode asset type");
                // Add an allowed conversion to the Merkle tree if we are on an
                // asset from a preceding epoch.
                let leaf_pos = if epoch < TARGET_MASP_EPOCH {
                    reward += reward_delta(epoch, digit);
                    conv_notes.push(Node::new(reward.cmu().to_repr()));
                    conv_notes.len() - 1
                } else {
                    // Otherwise use a sentinel value for the note position
                    usize::MAX
                };
                // Construct the conversion leaf that can help decode and
                // convert the current asset type
                let leaf = ConversionLeaf {
                    token: token_address.clone(),
                    denom: denomination,
                    digit_pos: digit,
                    epoch,
                    conversion: reward.clone(),
                    leaf_pos,
                };
                assets.insert(asset_type, leaf);
            }
        }
    }

    // Finally construct the entire conversion state
    let conversion_state = ConversionState {
        #[allow(deprecated)]
        current_precision: Some(NATIVE_PRECISION),
        tree: FrozenCommitmentTree::new(&conv_notes),
        assets,
    };
    let assets_hash = Hash::sha256(conversion_state.assets.serialize_to_vec());
    // Write the conversion state to the database and memory
    updates.push(migrations::DbUpdateType::Add {
        key: migrations::CONVERSION_STATE_KEY
            .parse()
            .expect("unable to construct conversion state key"),
        cf: DbColFam::STATE,
        value: conversion_state.into(),
        force: false,
    });

    // Put in storage only the assets hash because the size is quite large
    updates.push(migrations::DbUpdateType::Add {
        key: masp_assets_hash_key(),
        cf: DbColFam::SUBSPACE,
        value: assets_hash.into(),
        force: false,
    });
}

/// Demonstrate upgrading the transaction WASM code and hashes in storage
pub fn wasm_migration(updates: &mut Vec<migrations::DbUpdateType>) {
    // wasm_updates[x].0) The WASM hash that is being replaced
    // wasm_updates[x].1) The name of WASM being updated
    // wasm_updates[x].2) The bytes of the new WASM code
    const WASM_UPDATES: [(WasmHash, &str, WasmBytes); 2] = [
        (
            "83afcbf97c35188991ae2e73db2f48cb8d019c4295fe5323d9c3dfebcd5dbec0",
            "tx_transfer.wasm",
            // The following bytes are just an example. Usually the following
            // line will be: include_bytes!("<path to Wasm binary>"),
            &[0xDE, 0xAD, 0xBE, 0xEF],
        ),
        (
            "6ff3c2a2ebc65061a9b89abd15fb37851ca77e162b42b7989889bd537e802b09",
            "tx_ibc.wasm",
            // The following bytes are just an example. Usually the following
            // line will be: include_bytes!("<path to Wasm binary>"),
            &[0xDE, 0xAD, 0xBE, 0xEF],
        ),
    ];

    // Update the tx allowlist parameter
    let tx_allowlist_key = get_tx_allowlist_storage_key();
    const TX_ALLOWLIST: [WasmHash; 24] = [
        "ec357c39e05677da3d8da359fee6e3a8b9012dd1a7e7def51f4e484132f68c77",
        "a324288bdc7a7d3cb15ca5ef3ebb04b9121b1d5804478dabd1ef4533459d7069",
        "6012fff1d191a545d6f7960f1dd9b2df5fcdfc9dbb8dfd22bb1458f3983144b9",
        "4fe1bb1e76c21eacd5eb84782c51aebd683643eefbd1034e4e13aa7284f508f8",
        "23eec5e1bad79387e57d052840b86ff061aa3182638f690a642126183788f0e3",
        "5a31f468d03207a8e566a55072ddad7aad018fc635621564fb1c105b0f089f4d",
        "9eb40c4b40b5af540f9a32f8bd377a53cd3b5e0c3c799b4381ef6475f333e33d",
        "2b3cf66f49093f674793fcdba72d45f1d7c0e34556800f597d3d5242d97091e0",
        "6ff3c2a2ebc65061a9b89abd15fb37851ca77e162b42b7989889bd537e802b09",
        "31a7199befce4226faad7fe1744895fb6845ee0749016c3a2a0a31b26088aff9",
        "f0d270cab3357124eb8894c1e7cb0e775056ed613e41d075e23467bcaa36a1f7",
        "51c4d0149807597c1c7981cf28cb8b078c93843b7ae91a6cd9e6b422f343e9a3",
        "a07d722db5d3d06b0c65cb0c20811ce2a95105cebe2456a3ea6334eb2438fbab",
        "f1cdb278dae8b7ab28fd850dcf9746b03aee2b42444ec9e39ae3a0bd46f3e17c",
        "b48de32b91a58d8e63cd283bd96276f38736822ca8f90bfec2093eefdcdf5148",
        "83afcbf97c35188991ae2e73db2f48cb8d019c4295fe5323d9c3dfebcd5dbec0",
        "8293cecc00c63bb4b6216eec912c57c72544f42203ba1ff5a42ae098c9e921e4",
        "f0e37af0417f5d54f20c81c2cf1b9301bd13ce79695b78c85d11b2ba187fa86d",
        "0c650c7869da1ac3e734a4367557a499c937962effde4f7e7cc609278000ebd1",
        "dbb6f005883075ab4133d8bd367af914a899946e7ae532f816be48c77044a512",
        "bf4716b590b68562ee2c872757a0c370daf1504596d4350fffc0b94a566072ca",
        "f6330d8c8bc92d9f8ea0f023688873722b65291bc6db9bb11ab3a0836e1be86b",
        "c4357f5548c43086e56f22ac2e951ee2500368d8ed2479c0d0046b6e59f8a8e5",
        "b4261ecafcfb0254efb39165311268d99bb5aa85ac47514913317d20f1791790",
    ];
    let mut tx_allowlist: Vec<String> = TX_ALLOWLIST
        .into_iter()
        .map(|hash_str| {
            Hash::from_str(hash_str).unwrap().to_string().to_lowercase()
        })
        .collect();
    // Replace the targetted old hashes
    for (old_code_hash, name, code) in WASM_UPDATES {
        let old_code_hash = Hash::from_str(old_code_hash).unwrap();
        let new_code_hash = Hash(*Sha256::digest(code).as_ref());
        let new_code_len = u64::try_from(code.len()).unwrap();
        let pos = tx_allowlist
            .iter()
            .position(|x| Hash::from_str(x).unwrap() == old_code_hash)
            .expect("old tx code hash not found");
        tx_allowlist[pos] = new_code_hash.to_string().to_lowercase();

        // Delete the old tx code
        let old_code_key = Key::wasm_code(&old_code_hash);
        let old_code_len_key = Key::wasm_code_len(&old_code_hash);
        updates.push(migrations::DbUpdateType::Delete(
            old_code_key,
            DbColFam::SUBSPACE,
        ));
        updates.push(migrations::DbUpdateType::Delete(
            old_code_len_key,
            DbColFam::SUBSPACE,
        ));

        // Write the new tx code into storage
        let code_key = Key::wasm_code(&new_code_hash);
        let code_len_key = Key::wasm_code_len(&new_code_hash);
        let hash_key = Key::wasm_hash(name);
        let code_hash_key = Key::wasm_code_hash(name.to_owned());
        let code_name_key = Key::wasm_code_name(&new_code_hash);

        updates.push(migrations::DbUpdateType::Add {
            key: code_key,
            cf: DbColFam::SUBSPACE,
            value: code.to_vec().into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: code_len_key,
            cf: DbColFam::SUBSPACE,
            value: new_code_len.into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: hash_key,
            cf: DbColFam::SUBSPACE,
            value: new_code_hash.into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: code_hash_key,
            cf: DbColFam::SUBSPACE,
            value: new_code_hash.into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: code_name_key,
            cf: DbColFam::SUBSPACE,
            value: name.to_string().into(),
            force: false,
        });
    }
    // Put the allow list in storage
    updates.push(migrations::DbUpdateType::Add {
        key: tx_allowlist_key,
        cf: DbColFam::SUBSPACE,
        value: tx_allowlist.into(),
        force: false,
    });
}

/// Demonstrate how to set the shielded reward parameters of IBC tokens using a
/// migration
pub fn shielded_reward_parameters_migration(
    updates: &mut Vec<migrations::DbUpdateType>,
) {
    const TOKENS: [(
        Denomination,
        TokenAddress,
        MaxRewardRate,
        TargetLockedAmount,
        KpGain,
        KdGain,
    ); 6] = [
        (
            Denomination(0),
            TokenAddress::Ibc("channel-1", "uosmo"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
        (
            Denomination(0),
            TokenAddress::Ibc("channel-2", "uatom"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
        (
            Denomination(0),
            TokenAddress::Ibc("channel-3", "utia"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
        (
            Denomination(0),
            TokenAddress::Ibc("channel-0", "stuosmo"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
        (
            Denomination(0),
            TokenAddress::Ibc("channel-0", "stuatom"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
        (
            Denomination(0),
            TokenAddress::Ibc("channel-0", "stutia"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
    ];

    // Set IBC token shielded reward parameters
    for (denomination, token_addr, max_reward, lock_target, kp, kd) in TOKENS {
        // Compute the Namada address
        let token_address = match token_addr {
            TokenAddress::Ibc(channel_id, base_token) => {
                let ibc_denom = format!("transfer/{channel_id}/{base_token}");
                ibc_token(&ibc_denom).clone()
            }
            TokenAddress::Address(addr) => Address::from_str(addr)
                .expect("unable to construct token address"),
        };

        // The keys holding the shielded reward parameters of current token
        let shielded_token_max_rewards_key =
            masp_max_reward_rate_key::<Store<()>>(&token_address);
        let shielded_token_target_locked_amount_key =
            masp_locked_amount_target_key::<Store<()>>(&token_address);
        let shielded_token_kp_gain_key =
            masp_kp_gain_key::<Store<()>>(&token_address);
        let shielded_token_kd_gain_key =
            masp_kd_gain_key::<Store<()>>(&token_address);

        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_max_rewards_key,
            cf: DbColFam::SUBSPACE,
            value: Dec::from_str(max_reward).unwrap().into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_target_locked_amount_key,
            cf: DbColFam::SUBSPACE,
            value: Amount::from_uint(lock_target, denomination).unwrap().into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_kp_gain_key,
            cf: DbColFam::SUBSPACE,
            value: Dec::from_str(kp).unwrap().into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_kd_gain_key,
            cf: DbColFam::SUBSPACE,
            value: Dec::from_str(kd).unwrap().into(),
            force: false,
        });
    }
}

/// Demonstrate accelerating epochs
pub fn accelerate_epoch_migration(updates: &mut Vec<migrations::DbUpdateType>) {
    // Set the number of epochs per year to the specified constant
    const EPOCHS_PER_YEAR: u64 = 175200;
    let epochs_per_year_key = get_epochs_per_year_key();
    updates.push(migrations::DbUpdateType::Add {
        key: epochs_per_year_key,
        cf: DbColFam::SUBSPACE,
        value: EPOCHS_PER_YEAR.into(),
        force: false,
    });
    // Set the MASP epoch multiplier to the specified constant
    const MASP_EPOCH_MULTIPLIER: u64 = 2;
    let masp_epoch_multiplier_key = get_masp_epoch_multiplier_key();
    updates.push(migrations::DbUpdateType::Add {
        key: masp_epoch_multiplier_key,
        cf: DbColFam::SUBSPACE,
        value: MASP_EPOCH_MULTIPLIER.into(),
        force: false,
    });
    // Set the epoch duration to the specified constant
    const MIN_NUM_OF_BLOCKS: u64 = 4;
    let epy_i64 = i64::try_from(EPOCHS_PER_YEAR)
        .expect("`epochs_per_year` must not exceed `i64::MAX`");
    #[allow(clippy::arithmetic_side_effects)]
    let min_duration: i64 = 60 * 60 * 24 * 365 / epy_i64;
    let epoch_duration = EpochDuration {
        min_num_of_blocks: MIN_NUM_OF_BLOCKS,
        min_duration: namada_sdk::time::Duration::seconds(min_duration).into(),
    };
    let epoch_duration_key = get_epoch_duration_storage_key();
    updates.push(migrations::DbUpdateType::Add {
        key: epoch_duration_key,
        cf: DbColFam::SUBSPACE,
        value: epoch_duration.into(),
        force: false,
    });
    // Set the next epoch's block height to zero in order to force transition
    updates.push(migrations::DbUpdateType::Add {
        key: migrations::NEXT_EPOCH_MIN_START_HEIGHT_KEY
            .parse()
            .expect("unable to construct conversion state key"),
        cf: DbColFam::STATE,
        value: BlockHeight(0).into(),
        force: false,
    });
    // Set the next epoch's start time to a minimum in order to force transition
    updates.push(migrations::DbUpdateType::Add {
        key: migrations::NEXT_EPOCH_MIN_START_TIME_KEY
            .parse()
            .expect("unable to construct conversion state key"),
        cf: DbColFam::STATE,
        value: MIN_UTC.into(),
        force: false,
    });
}

/// Generate various migrations
pub fn main() {
    // Write an example migration that updates minted balances
    let mut minted_balance_changes = migrations::DbChanges { changes: vec![] };
    minted_balance_migration(&mut minted_balance_changes.changes);
    std::fs::write(
        "minted_balance_migration.json",
        serde_json::to_string(&minted_balance_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that updates token precision
    let mut reward_precision_changes =
        migrations::DbChanges { changes: vec![] };
    shielded_reward_precision_migration(&mut reward_precision_changes.changes);
    std::fs::write(
        "reward_precision_migration.json",
        serde_json::to_string(&reward_precision_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that resets shielded rewards
    let mut reward_reset_changes = migrations::DbChanges { changes: vec![] };
    shielded_reward_reset_migration(&mut reward_reset_changes.changes);
    std::fs::write(
        "reward_reset_migration.json",
        serde_json::to_string(&reward_reset_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that directly updates conversion state
    let mut conversion_state_changes =
        migrations::DbChanges { changes: vec![] };
    conversion_state_migration(&mut conversion_state_changes.changes);
    std::fs::write(
        "conversion_state_migration.json",
        serde_json::to_string(&conversion_state_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that just updates WASMs
    let mut wasm_changes = migrations::DbChanges { changes: vec![] };
    wasm_migration(&mut wasm_changes.changes);
    std::fs::write(
        "wasm_migration.json",
        serde_json::to_string(&wasm_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that updates WASMs and resets shielded rewards
    let mut pre_phase4_changes = migrations::DbChanges { changes: vec![] };
    shielded_reward_reset_migration(&mut pre_phase4_changes.changes);
    wasm_migration(&mut pre_phase4_changes.changes);
    std::fs::write(
        "pre_phase4_migration.json",
        serde_json::to_string(&pre_phase4_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that sets shielded reward parameters
    let mut reward_parameter_changes =
        migrations::DbChanges { changes: vec![] };
    shielded_reward_parameters_migration(&mut reward_parameter_changes.changes);
    std::fs::write(
        "reward_parameters_migration.json",
        serde_json::to_string(&reward_parameter_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that accelerates epochs
    let mut accelerate_epochs_changes =
        migrations::DbChanges { changes: vec![] };
    accelerate_epoch_migration(&mut accelerate_epochs_changes.changes);
    std::fs::write(
        "accelerate_epochs_migration.json",
        serde_json::to_string(&accelerate_epochs_changes).unwrap(),
    )
    .unwrap();
}
