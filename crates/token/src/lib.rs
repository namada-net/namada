//! Namada transparent and shielded token types, storage keys and storage
//! fns.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]
#![cfg_attr(feature = "arbitrary", allow(clippy::disallowed_methods))]

use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_events::EmitEvents;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
pub use namada_shielded_token::*;
use namada_systems::parameters;
pub use namada_trans_token::*;

pub mod tx;

/// Validity predicates
pub mod vp {
    pub use namada_shielded_token::vp::MaspVp;
    // The error and result type are the same as in `namada_trans_token` -
    // a native VP
    pub use namada_shielded_token::{Error, Result};
    pub use namada_trans_token::vp::MultitokenVp;
}

use serde::{Deserialize, Serialize};

/// Token storage keys
pub mod storage_key {
    use namada_core::address::Address;
    use namada_core::storage;
    use namada_shielded_token::storage_key as shielded;
    pub use namada_shielded_token::storage_key::{
        is_masp_base_native_precision_key, is_masp_commitment_anchor_key,
        is_masp_key, is_masp_nullifier_key,
        is_masp_scheduled_base_native_precision_key,
        is_masp_scheduled_reward_precision_key, is_masp_token_map_key,
        is_masp_transfer_key, masp_assets_hash_key,
        masp_base_native_precision_key, masp_commitment_anchor_key,
        masp_commitment_tree_key, masp_conversion_key, masp_convert_anchor_key,
        masp_nullifier_key, masp_scheduled_base_native_precision_key,
        masp_scheduled_reward_precision_key, masp_token_map_key,
        masp_total_rewards,
    };
    pub use namada_trans_token::storage_key::*;

    type TransToken = namada_trans_token::Store<()>;

    /// Obtain the nominal proportional key for the given token
    pub fn masp_kp_gain_key(token_addr: &Address) -> storage::Key {
        shielded::masp_kp_gain_key::<TransToken>(token_addr)
    }

    /// Obtain the nominal derivative key for the given token
    pub fn masp_kd_gain_key(token_addr: &Address) -> storage::Key {
        shielded::masp_kd_gain_key::<TransToken>(token_addr)
    }

    /// The max reward rate key for the given token
    pub fn masp_max_reward_rate_key(token_addr: &Address) -> storage::Key {
        shielded::masp_max_reward_rate_key::<TransToken>(token_addr)
    }

    /// The shielded rewards precision key for the given token
    pub fn masp_reward_precision_key(token_addr: &Address) -> storage::Key {
        shielded::masp_reward_precision_key::<TransToken>(token_addr)
    }

    /// Obtain the locked target amount key for the given token
    pub fn masp_locked_amount_target_key(token_addr: &Address) -> storage::Key {
        shielded::masp_locked_amount_target_key::<TransToken>(token_addr)
    }

    /// Obtain the storage key for the last locked amount of a token
    pub fn masp_last_locked_amount_key(token_addr: &Address) -> storage::Key {
        shielded::masp_last_locked_amount_key::<TransToken>(token_addr)
    }

    /// Obtain the storage key for the last inflation of a token
    pub fn masp_last_inflation_key(token_addr: &Address) -> storage::Key {
        shielded::masp_last_inflation_key::<TransToken>(token_addr)
    }
}

/// Initialize parameters for the token in storage during the genesis block.
pub fn write_params<S>(
    params: &Option<ShieldedParams>,
    storage: &mut S,
    address: &Address,
    denom: &Denomination,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    namada_trans_token::write_params(storage, address)?;
    if let Some(params) = params {
        namada_shielded_token::write_params::<S, namada_trans_token::Store<()>>(
            params, storage, address, denom,
        )?;
    }
    Ok(())
}

/// Apply token logic for finalizing block (i.e. shielded token rewards)
pub fn finalize_block<S, Params>(
    storage: &mut S,
    _events: &mut impl EmitEvents,
    is_new_masp_epoch: bool,
) -> Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
    Params: parameters::Read<S>,
{
    if is_new_masp_epoch {
        conversion::update_allowed_conversions::<S, Params, Store<S>>(storage)?;
    }
    Ok(())
}

/// Accounts can send or receive funds in a transparent token transfer
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct Account {
    /// Owner of the account
    pub owner: Address,
    /// Token handled by the account
    pub token: Address,
}

/// Arguments for a multi-party token transfer
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Default,
    Hash,
    Eq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct Transfer {
    /// Sources of this transfer
    pub sources: BTreeMap<Account, DenominatedAmount>,
    /// Targets of this transfer
    pub targets: BTreeMap<Account, DenominatedAmount>,
    /// Hash of tx section that contains the MASP transaction
    pub shielded_section_hash: Option<MaspTxId>,
}

/// References to the transparent sections of a [`Transfer`].
#[derive(Debug, Clone)]
pub struct TransparentTransfersRef<'a> {
    /// Sources of this transfer
    pub sources: &'a BTreeMap<Account, DenominatedAmount>,
    /// Targets of this transfer
    pub targets: &'a BTreeMap<Account, DenominatedAmount>,
}

impl Transfer {
    /// Create a MASP transaction
    pub fn masp(hash: MaspTxId) -> Self {
        Self {
            shielded_section_hash: Some(hash),
            ..Self::default()
        }
    }

    /// Set the key to the given amount
    fn set(
        map: &mut BTreeMap<Account, DenominatedAmount>,
        key: Account,
        val: DenominatedAmount,
    ) {
        if val.is_zero() {
            // Zero entries do not need to be present
            map.remove(&key);
        } else {
            map.insert(key, val);
        }
    }

    /// Debit the given account
    pub fn debit(
        mut self,
        owner: Address,
        token: Address,
        amount: DenominatedAmount,
    ) -> Option<Self> {
        let account = Account { owner, token };
        let zero = DenominatedAmount::new(Amount::zero(), amount.denom());
        let source_amount = *self.sources.get(&account).unwrap_or(&zero);
        let target_amount = *self.targets.get(&account).unwrap_or(&zero);
        // If this account is already a target, then reduce the target
        if amount < target_amount {
            // Account still gets net increase
            Self::set(
                &mut self.targets,
                account,
                target_amount.checked_sub(amount)?,
            );
        } else {
            // Account now actually gets a net decrease
            self.targets.remove(&account);
            let new_amt = source_amount
                .checked_add(amount.checked_sub(target_amount)?)?;
            Self::set(&mut self.sources, account, new_amt);
        }
        Some(self)
    }

    /// Credit the given account
    pub fn credit(
        mut self,
        owner: Address,
        token: Address,
        amount: DenominatedAmount,
    ) -> Option<Self> {
        let account = Account { owner, token };
        let zero = DenominatedAmount::new(Amount::zero(), amount.denom());
        let source_amount = *self.sources.get(&account).unwrap_or(&zero);
        let target_amount = *self.targets.get(&account).unwrap_or(&zero);
        // If this account is already a source, then reduce the source
        if amount < source_amount {
            // Account still gets net decrease
            Self::set(
                &mut self.sources,
                account,
                source_amount.checked_sub(amount)?,
            );
        } else {
            // Account now actually gets a net increase
            self.sources.remove(&account);
            let new_amt = target_amount
                .checked_add(amount.checked_sub(source_amount)?)?;
            Self::set(&mut self.targets, account, new_amt);
        }
        Some(self)
    }

    /// Transfer assets between accounts
    pub fn transfer(
        self,
        source: Address,
        target: Address,
        token: Address,
        amount: DenominatedAmount,
    ) -> Option<Self> {
        self.debit(source, token.clone(), amount)?
            .credit(target, token, amount)
    }

    /// Get references to the transparent sections.
    pub fn transparent_part(&self) -> Option<TransparentTransfersRef<'_>> {
        if self.sources.is_empty() && self.targets.is_empty() {
            None
        } else {
            Some(TransparentTransfersRef {
                sources: &self.sources,
                targets: &self.targets,
            })
        }
    }
}

impl TransparentTransfersRef<'_> {
    /// Construct pairs of source address and token with a debited amount
    pub fn sources(&self) -> BTreeMap<(Address, Address), Amount> {
        self.sources
            .iter()
            .map(|(account, amount)| {
                (
                    (account.owner.clone(), account.token.clone()),
                    amount.amount(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    }

    /// Construct pairs of target address and token with a credited amount
    pub fn targets(&self) -> BTreeMap<(Address, Address), Amount> {
        self.targets
            .iter()
            .map(|(account, amount)| {
                (
                    (account.owner.clone(), account.token.clone()),
                    amount.amount(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    }
}

/// Soft limit on the amount of transfer inputs and outputs
const TRANSFER_INOUT_LIMIT: usize = 20;

/// Validate the inputs and outputs in a transparent transfer.
pub fn validate_transfer_in_out(
    sources: &BTreeMap<Account, DenominatedAmount>,
    targets: &BTreeMap<Account, DenominatedAmount>,
) -> core::result::Result<(), String> {
    let total_inout = sources.len().saturating_add(targets.len());

    if total_inout > TRANSFER_INOUT_LIMIT {
        return Err(format!(
            "Transfer has {} inputs and {} outputs, which combined exceed the \
             limit of {TRANSFER_INOUT_LIMIT} total inputs and outputs",
            sources.len(),
            targets.len()
        ));
    }

    Ok(())
}

#[cfg(all(any(test, feature = "testing"), feature = "masp"))]
/// Testing helpers and strategies for tokens
pub mod testing {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[cfg(feature = "mainnet")]
    use masp_primitives::consensus::MainNetwork as Network;
    #[cfg(not(feature = "mainnet"))]
    use masp_primitives::consensus::TestNetwork as Network;
    use masp_primitives::consensus::testing::arb_height;
    use masp_primitives::merkle_tree::FrozenCommitmentTree;
    use masp_primitives::transaction::builder::Builder;
    use masp_primitives::transaction::components::sapling::builder::{
        RngBuildParams, StoredBuildParams,
    };
    use masp_primitives::transaction::components::{TxOut, U64Sum};
    use masp_primitives::transaction::fees::fixed::FeeRule;
    use masp_primitives::zip32::PseudoExtendedKey;
    use namada_core::address::testing::arb_non_internal_address;
    use namada_core::address::{Address, MASP};
    use namada_core::collections::HashMap;
    use namada_core::masp::{AssetData, TAddrData, encode_asset_type};
    pub use namada_core::token::*;
    use namada_shielded_token::masp::testing::{
        MockTxProver, TestCsprng, arb_masp_epoch, arb_output_descriptions,
        arb_pre_asset_type, arb_rng, arb_spend_descriptions,
    };
    use namada_shielded_token::masp::{NETWORK, ShieldedTransfer, WalletMap};
    pub use namada_trans_token::testing::*;
    use proptest::collection;
    use proptest::prelude::*;
    use proptest::sample::SizeRange;

    use super::Transfer;

    // Maximum value for a note partition
    const MAX_MONEY: u64 = 100;
    // Maximum number of partitions for a note
    const MAX_SPLITS: usize = 3;

    prop_compose! {
        /// Generate a transparent transfer
        fn arb_single_transparent_transfer()(
            source in arb_non_internal_address(),
            target in arb_non_internal_address(),
            token in arb_non_internal_address(),
            amount in arb_denominated_amount(),
        ) -> (Address, Address, Address, DenominatedAmount) {
            (
                source,
                target,
                token,
                amount,
            )
        }
    }

    /// Generate a vectorized transparent transfer
    pub fn arb_transparent_transfer(
        number_of_txs: impl Into<SizeRange>,
    ) -> impl Strategy<Value = Transfer> {
        collection::vec(arb_single_transparent_transfer(), number_of_txs)
            .prop_filter_map("Transfers must not overflow", |data| {
                data.into_iter().try_fold(
                    Transfer::default(),
                    |acc, (source, target, token, amount)| {
                        acc.transfer(source, target, token, amount)
                    },
                )
            })
    }

    prop_compose! {
        /// Generate an arbitrary shielded MASP transaction builder
        #[allow(clippy::arithmetic_side_effects)]
        pub fn arb_shielded_builder(asset_range: impl Into<SizeRange>)(
            assets in collection::hash_map(
                arb_pre_asset_type(),
                collection::vec(..MAX_MONEY, ..MAX_SPLITS),
                asset_range,
            ),
        )(
            expiration_height in arb_height(masp_primitives::consensus::BranchId::MASP, &Network),
            spend_descriptions in assets
                .iter()
                .map(|(asset, values)| arb_spend_descriptions(asset.clone(), values.clone()))
                .collect::<Vec<_>>(),
            output_descriptions in assets
                .iter()
                .map(|(asset, values)| arb_output_descriptions(asset.clone(), values.clone()))
                .collect::<Vec<_>>(),
            input_data in collection::vec((any::<bool>(), arb_non_internal_address()), assets.len() * MAX_SPLITS),
            output_data in collection::vec((any::<bool>(), arb_non_internal_address()), assets.len() * MAX_SPLITS),
            assets in Just(assets),
        ) -> (
            Transfer,
            Builder::<Network, PseudoExtendedKey>,
            HashMap<AssetData, u64>,
        ) {
            // Enable assets to be more easily decoded
            let mut asset_decoder = BTreeMap::new();
            for asset_data in assets.keys() {
                let asset_type = encode_asset_type(
                    asset_data.token.clone(),
                    asset_data.denom,
                    asset_data.position,
                    asset_data.epoch,
                ).unwrap();
                asset_decoder.insert(asset_type, asset_data);
            }
            let mut transfer = Transfer::default();
            let mut builder = Builder::<Network, _>::new(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
            );
            let mut leaves = Vec::new();
            // First construct a Merkle tree containing all notes to be used
            for (_esk, _div, _note, node) in spend_descriptions.iter().flatten() {
                leaves.push(*node);
            }
            let tree = FrozenCommitmentTree::new(&leaves);
            // Then use the notes knowing that they all have the same anchor
            for ((is_shielded, address), (idx, (esk, div, note, _node))) in
                input_data.into_iter().zip(spend_descriptions.iter().flatten().enumerate())
            {
                // Compute the equivalent transparent movement
                let asset_data = asset_decoder[&note.asset_type];
                let amount = DenominatedAmount::new(
                    Amount::from_masp_denominated(note.value, asset_data.position),
                    asset_data.denom,
                );
                // Use either a transparent input or a shielded input
                if is_shielded {
                    builder.add_sapling_spend(*esk, *div, *note, tree.path(idx)).unwrap();
                    transfer = transfer.debit(MASP, asset_data.token.clone(), amount).unwrap();
                } else {
                    let txout = TxOut {
                        address: TAddrData::Addr(address.clone()).taddress(),
                        asset_type: note.asset_type,
                        value: note.value,
                    };
                    builder.add_transparent_input(txout).unwrap();
                    transfer = transfer.debit(address, asset_data.token.clone(), amount).unwrap();
                }
            }
            for ((is_shielded, address), (ovk, payment_addr, asset_type, value, memo)) in
                output_data.into_iter().zip(output_descriptions.into_iter().flatten())
            {
                // Compute the equivalent transparent movement
                let asset_data = asset_decoder[&asset_type];
                let amount = DenominatedAmount::new(
                    Amount::from_masp_denominated(value, asset_data.position),
                    asset_data.denom,
                );
                // Use either a transparent output or a shielded output
                if is_shielded {
                    builder.add_sapling_output(ovk, payment_addr, asset_type, value, memo).unwrap();
                    transfer = transfer.credit(MASP, asset_data.token.clone(), amount).unwrap();
                } else {
                    builder.add_transparent_output(
                        &TAddrData::Addr(address.clone()).taddress(),
                        asset_type,
                        value,
                    ).unwrap();
                    transfer = transfer.credit(address, asset_data.token.clone(), amount).unwrap();
                }
            }
            (transfer, builder, assets.into_iter().map(|(k, v)| (k, v.iter().sum())).collect())
        }
    }

    prop_compose! {
        /// Generate an arbitrary MASP shielded transfer
        pub fn arb_shielded_transfer(
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (mut transfer, builder, asset_types) in arb_shielded_builder(asset_range),
            epoch in arb_masp_epoch(),
            prover_rng in arb_rng().prop_map(TestCsprng),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
        ) -> (Transfer, ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams) {
            let mut rng_build_params = RngBuildParams::new(bparams_rng);
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut rng_build_params,
            ).unwrap();
            transfer.shielded_section_hash = Some(masp_tx.txid().into());
            (transfer, ShieldedTransfer {
                builder: builder.map_builder(WalletMap),
                metadata,
                masp_tx,
                epoch,
            }, asset_types, rng_build_params.to_stored().unwrap())
        }
    }
}

#[cfg(test)]
mod test_token_transfer_actions {
    use namada_core::address::testing::{established_address_1, nam};
    use namada_core::address::{self};
    use namada_core::storage::DbKeySeg;
    use namada_shielded_token::storage_key::is_masp_balance_key;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn test_set_to_zero() {
        let account = Account {
            owner: established_address_1(),
            token: nam(),
        };

        let mut transfer = Transfer::default();

        let zero = Amount::zero().native_denominated();
        Transfer::set(&mut transfer.sources, account.clone(), zero);
        assert_eq!(transfer, Transfer::default());

        let one = Amount::from(1).native_denominated();
        Transfer::set(&mut transfer.sources, account.clone(), one);
        assert_eq!(
            transfer,
            Transfer {
                sources: BTreeMap::from([(account, one)]),
                ..Transfer::default()
            }
        );
    }

    #[test]
    fn test_debit_credit() {
        // test debit
        test_debit_credit_aux(
            Transfer::debit,
            Transfer::credit,
            |sources| Transfer {
                sources,
                ..Transfer::default()
            },
            |targets| Transfer {
                targets,
                ..Transfer::default()
            },
        );

        // test credit
        test_debit_credit_aux(
            Transfer::credit,
            Transfer::debit,
            |targets| Transfer {
                targets,
                ..Transfer::default()
            },
            |sources| Transfer {
                sources,
                ..Transfer::default()
            },
        );
    }

    fn test_debit_credit_aux(
        op1: fn(
            Transfer,
            Address,
            Address,
            DenominatedAmount,
        ) -> Option<Transfer>,
        op2: fn(
            Transfer,
            Address,
            Address,
            DenominatedAmount,
        ) -> Option<Transfer>,
        transfer1: fn(BTreeMap<Account, DenominatedAmount>) -> Transfer,
        transfer2: fn(BTreeMap<Account, DenominatedAmount>) -> Transfer,
    ) {
        let account = Account {
            owner: established_address_1(),
            token: nam(),
        };

        let amount_100 = Amount::native_whole(100).native_denominated();
        let amount_90 = Amount::native_whole(90).native_denominated();
        let amount_80 = Amount::native_whole(80).native_denominated();
        let amount_10 = Amount::native_whole(10).native_denominated();

        let transfer = Transfer::default();

        let transfer = op1(
            transfer,
            account.owner.clone(),
            account.token.clone(),
            amount_10,
        )
        .unwrap();

        assert_eq!(
            transfer,
            transfer1(BTreeMap::from([(account.clone(), amount_10)])),
        );

        let transfer = op2(
            transfer,
            account.owner.clone(),
            account.token.clone(),
            amount_100,
        )
        .unwrap();

        assert_eq!(
            transfer,
            transfer2(BTreeMap::from([(account.clone(), amount_90)])),
        );

        let transfer = op1(
            transfer,
            account.owner.clone(),
            account.token.clone(),
            amount_10,
        )
        .unwrap();

        assert_eq!(
            transfer,
            transfer2(BTreeMap::from([(account.clone(), amount_80)])),
        );
    }

    /// Check that the MASP balance key is a transparent balance key.
    #[test]
    fn test_masp_trans_balance_key() {
        let token = nam();
        let key = namada_trans_token::storage_key::balance_key(
            &token,
            &address::MASP,
        );
        assert!(is_masp_balance_key(&key));

        // Replace the token address and check that it still matches
        let mut another_token_key = key.clone();
        another_token_key.segments[1] =
            DbKeySeg::AddressSeg(address::testing::gen_established_address());
        assert!(is_masp_balance_key(&another_token_key));

        // Replace one of the non-token segments with some random string or
        // address and check that it no longer matches.
        // Skip index 1 which is the token address.
        for segment_num in [0, 2, 3] {
            let mut key = key.clone();
            key.segments[segment_num] = match &key.segments[segment_num] {
                DbKeySeg::AddressSeg(_) => DbKeySeg::AddressSeg(
                    address::testing::gen_established_address(),
                ),
                DbKeySeg::StringSeg(_) => {
                    DbKeySeg::StringSeg("Dangus".to_string())
                }
            };
            assert!(!is_masp_balance_key(&key));
        }
    }

    /// The number of unique transfer addresses allowed, per sink
    /// (i.e. input and output vector).
    ///
    /// Since the limit is computed by summing the inputs and outputs,
    /// if all addresses are distinct, sources and targets alike can
    /// have at most `TRANSFER_INOUT_LIMIT / 2` elements.
    const TRANSFER_INOUT_SINK_UNIQUE: usize = TRANSFER_INOUT_LIMIT / 2;

    /// Test the validation of transparent transfers exceeding the
    /// limit of inputs and outputs.
    #[test]
    fn test_transparent_transfer_validation_exceeding_limit() {
        fn r#gen(id: usize) -> (Account, DenominatedAmount) {
            let id = u64::try_from(id).unwrap();
            let addr = {
                let mut addr = [0u8; 20];
                addr[..8].copy_from_slice(&id.to_ne_bytes());
                Address::Established(addr.into())
            };

            let account = Account {
                owner: addr.clone(),
                token: addr,
            };
            let amount = DenominatedAmount::native(id.into());

            (account, amount)
        }

        let sources: BTreeMap<_, _> =
            (0..TRANSFER_INOUT_SINK_UNIQUE).map(r#gen).collect();
        let targets: BTreeMap<_, _> = (TRANSFER_INOUT_SINK_UNIQUE..)
            .take(TRANSFER_INOUT_SINK_UNIQUE + 1)
            .map(r#gen)
            .collect();

        assert_eq!(sources.len() + targets.len(), TRANSFER_INOUT_LIMIT + 1);

        assert!(
            validate_transfer_in_out(&sources, &targets,).is_err(),
            "sources {}, targets {}",
            sources.len(),
            targets.len()
        );
    }

    proptest! {
        /// Test the validation of transparent transfers under the
        /// limit of inputs and outputs.
        #[test]
        fn test_transparent_transfer_validation_under_limit(
            transfer in testing::arb_transparent_transfer(
                0..=TRANSFER_INOUT_SINK_UNIQUE,
            )
        ) {
            prop_assert!(
                validate_transfer_in_out(
                    &transfer.sources,
                    &transfer.targets,
                )
                .is_ok(),
                "sources {}, targets {}",
                transfer.sources.len(),
                transfer.targets.len()
            );
        }
    }
}
