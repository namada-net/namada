//! MASP rewards conversions

#[cfg(any(feature = "multicore", test))]
use std::collections::BTreeMap;

#[cfg(any(feature = "multicore", test))]
use masp_primitives::asset_type::AssetType;
#[cfg(any(feature = "multicore", test))]
use masp_primitives::convert::{AllowedConversion, UncheckedAllowedConversion};
#[cfg(any(feature = "multicore", test))]
use masp_primitives::transaction::components::I128Sum as MaspAmount;
use namada_controller::PDController;
use namada_core::address::{Address, MASP};
#[cfg(any(feature = "multicore", test))]
use namada_core::arith::CheckedAdd;
use namada_core::arith::checked;
#[cfg(any(feature = "multicore", test))]
use namada_core::borsh::BorshSerializeExt;
use namada_core::dec::Dec;
#[cfg(any(feature = "multicore", test))]
use namada_core::hash::Hash;
use namada_core::masp::Precision;
#[cfg(any(feature = "multicore", test))]
use namada_core::masp::{MaspEpoch, encode_asset_type};
#[cfg(any(feature = "multicore", test))]
use namada_core::token::MaspDigitPos;
use namada_core::token::{Amount, DenominatedAmount, Denomination};
use namada_core::uint::Uint;
#[cfg(any(feature = "multicore", test))]
use namada_state::iter_prefix_with_filter_map;
use namada_systems::{parameters, trans_token};

#[cfg(any(feature = "multicore", test))]
use crate::storage_key::{
    is_masp_conversion_key, is_masp_scheduled_reward_precision_key,
    masp_assets_hash_key, masp_conversion_key_prefix,
    masp_scheduled_base_native_precision_key,
    masp_scheduled_reward_precision_key_prefix, masp_token_map_key,
};
use crate::storage_key::{
    masp_base_native_precision_key, masp_kd_gain_key, masp_kp_gain_key,
    masp_last_inflation_key, masp_last_locked_amount_key,
    masp_locked_amount_target_key, masp_max_reward_rate_key,
    masp_reward_precision_key,
};
#[cfg(any(feature = "multicore", test))]
use crate::{ConversionLeaf, Error, OptionExt, ResultExt};
use crate::{Result, StorageRead, StorageWrite, WithConversionState};

/// Compute shielded token inflation amount
#[allow(clippy::too_many_arguments)]
pub fn compute_inflation(
    locked_amount: Uint,
    total_native_amount: Uint,
    max_reward_rate: Dec,
    last_inflation_amount: Uint,
    p_gain_nom: Dec,
    d_gain_nom: Dec,
    epochs_per_year: u64,
    target_amount: Dec,
    last_amount: Dec,
) -> Uint {
    let controller = PDController::new(
        total_native_amount,
        max_reward_rate,
        last_inflation_amount,
        p_gain_nom,
        d_gain_nom,
        epochs_per_year,
        target_amount,
        last_amount,
    );

    let metric = Dec::try_from(locked_amount)
        .expect("Should not fail to convert Uint to Dec");
    let control_coeff = max_reward_rate
        .checked_div(controller.get_epochs_per_year())
        .expect("Control coefficient overflow");

    tracing::debug!(
        "Shielded token inflation inputs: {controller:#?}, metric: {metric}, \
         coefficient: {control_coeff}"
    );
    controller
        .compute_inflation(control_coeff, metric)
        .expect("Inflation calculation overflow")
}

// Infer the precision of a token from its denomination
#[deprecated = "Token precisions are now read from storage instead of being \
                inferred from their denominations."]
fn infer_token_precision<S, TransToken>(
    storage: &mut S,
    addr: &Address,
) -> Result<Precision>
where
    S: StorageWrite + StorageRead + WithConversionState,
    TransToken: trans_token::Read<S>,
{
    // Since reading reward precision has failed, choose a
    // thousandth of the given token. But clamp the precision above
    // by 10^38, the maximum power of 10 that can be contained by a
    // u128.
    let denomination = TransToken::read_denom(storage, addr)?
        .expect("failed to read token denomination");
    let precision_denom =
        u32::from(denomination.0).saturating_sub(3).clamp(0, 38);
    let reward_precision = checked!(10u128 ^ precision_denom)?;
    Ok(reward_precision)
}

// Read the base native precision from storage. And if it is not initialized,
// fall back to inferring it based on native denomination.
fn read_base_native_precision<S, TransToken>(
    storage: &mut S,
    native_token: &Address,
) -> Result<Precision>
where
    S: StorageWrite + StorageRead + WithConversionState,
    TransToken: trans_token::Keys + trans_token::Read<S>,
{
    let base_native_precision_key = masp_base_native_precision_key();
    storage.read(&base_native_precision_key)?.map_or_else(
        || -> Result<Precision> {
            #[allow(deprecated)]
            let precision =
                infer_token_precision::<_, TransToken>(storage, native_token)?;
            storage.write(&base_native_precision_key, precision)?;
            Ok(precision)
        },
        Ok,
    )
}

/// Compute the precision of MASP rewards for the given token. This function
/// must be a non-zero constant for a given token.
pub fn calculate_masp_rewards_precision<S, TransToken>(
    storage: &mut S,
    addr: &Address,
) -> Result<Precision>
where
    S: StorageWrite + StorageRead + WithConversionState,
    TransToken: trans_token::Keys + trans_token::Read<S>,
{
    // Inflation is implicitly denominated by this value. The lower this
    // figure, the less precise inflation computations are. This is especially
    // problematic when inflation is coming from a token with much higher
    // denomination than the native token. The higher this figure, the higher
    // the threshold of holdings required in order to receive non-zero rewards.
    // This value should be fixed constant for each asset type. Here we read a
    // value from storage and failing that we choose a thousandth of the given
    // asset.
    // Key to read/write reward precision from
    let reward_precision_key = masp_reward_precision_key::<TransToken>(addr);
    // Now read the desired reward precision for this token address
    let reward_precision: Precision =
        storage.read(&reward_precision_key)?.map_or_else(
            || -> Result<Precision> {
                let native_token = storage.get_native_token()?;
                #[allow(deprecated)]
                let prec = match storage.conversion_state().current_precision {
                    // If this is the native token, then the precision was
                    // actually stored in the conversion state.
                    Some(native_precision) if *addr == native_token => {
                        native_precision
                    }
                    // If the current precision is not defined for the native
                    // token, then attempt to get it from the base native
                    // precision.
                    None if *addr == native_token => {
                        read_base_native_precision::<_, TransToken>(
                            storage, addr,
                        )?
                    }
                    // Otherwise default to inferring the precision from the
                    // token denomination
                    _ => infer_token_precision::<_, TransToken>(storage, addr)?,
                };
                // Record the precision that is now being used so that it does
                // not have to be recomputed each time, and to ensure that this
                // value is not accidentally changed even by a change to this
                // initialization algorithm.
                storage.write(&reward_precision_key, prec)?;
                Ok(prec)
            },
            Ok,
        )?;

    Ok(reward_precision)
}

/// Get the balance of the given token at the MASP address that is eligble to
/// receive rewards.
fn get_masp_dated_balance<S, TransToken>(
    storage: &mut S,
    token: &Address,
) -> Result<Amount>
where
    S: StorageWrite + StorageRead,
    TransToken: trans_token::Keys + trans_token::Read<S>,
{
    use crate::read_undated_balance;
    let masp_addr = MASP;

    // total locked amount in the Shielded pool
    let total_tokens_in_masp =
        TransToken::read_balance(storage, token, &masp_addr)?;
    // Since dated and undated tokens are stored together in the pool, subtract
    // the latter to get the dated balance
    let masp_undated_balance = read_undated_balance(storage, token)?;
    Ok(checked!(total_tokens_in_masp - masp_undated_balance)?)
}

/// Compute the MASP rewards by applying the PD-controller to the genesis
/// parameters and the last inflation and last locked rewards ratio values.
pub fn calculate_masp_rewards<S, TransToken>(
    storage: &mut S,
    token: &Address,
    denomination: Denomination,
    precision: Precision,
    masp_epochs_per_year: u64,
) -> Result<(u128, Precision)>
where
    S: StorageWrite + StorageRead,
    TransToken: trans_token::Keys + trans_token::Read<S>,
{
    let masp_addr = MASP;

    // Query the storage for information -------------------------

    //// information about the amount of native tokens on the chain
    let total_native_tokens =
        TransToken::get_effective_total_native_supply(storage)?;

    // total locked amount in the Shielded pool
    let total_tokens_in_masp =
        TransToken::read_balance(storage, token, &masp_addr)?;

    //// Values from the last epoch
    let last_inflation: Amount = storage
        .read(&masp_last_inflation_key::<TransToken>(token))?
        .expect("failure to read last inflation");

    let last_locked_amount: Amount = storage
        .read(&masp_last_locked_amount_key::<TransToken>(token))?
        .expect("failure to read last inflation");

    //// Parameters for each token
    let max_reward_rate: Dec = storage
        .read(&masp_max_reward_rate_key::<TransToken>(token))?
        .expect("max reward should properly decode");

    let kp_gain_nom: Dec = storage
        .read(&masp_kp_gain_key::<TransToken>(token))?
        .expect("kp_gain_nom reward should properly decode");

    let kd_gain_nom: Dec = storage
        .read(&masp_kd_gain_key::<TransToken>(token))?
        .expect("kd_gain_nom reward should properly decode");

    let target_locked_amount: Amount = storage
        .read(&masp_locked_amount_target_key::<TransToken>(token))?
        .expect("locked ratio target should properly decode");

    let target_locked_dec = Dec::try_from(target_locked_amount.raw_amount())
        .expect("Should not fail to convert Uint to Dec");
    let last_locked_dec = Dec::try_from(last_locked_amount.raw_amount())
        .expect("Should not fail to convert Uint to Dec");

    // Initial computation of the new shielded inflation
    let inflation = compute_inflation(
        total_tokens_in_masp.raw_amount(),
        total_native_tokens.raw_amount(),
        max_reward_rate,
        last_inflation.raw_amount(),
        kp_gain_nom,
        kd_gain_nom,
        masp_epochs_per_year,
        target_locked_dec,
        last_locked_dec,
    );

    // total locked amount in the Shielded pool
    let rewardable_tokens_in_masp =
        get_masp_dated_balance::<S, TransToken>(storage, token)?;

    // inflation-per-token = inflation / locked tokens = n/PRECISION
    // ∴ n = (inflation * PRECISION) / locked tokens
    // Since we must put the notes in a compatible format with the
    // note format, we must make the inflation amount discrete.
    let noterized_inflation = if rewardable_tokens_in_masp.is_zero() {
        0u128
    } else {
        inflation
            .checked_mul_div(
                Uint::from(precision),
                rewardable_tokens_in_masp.raw_amount(),
            )
            .and_then(|x| x.0.try_into().ok())
            .unwrap_or_else(|| {
                tracing::warn!(
                    "MASP inflation for {} assumed to be 0 because the \
                     computed value is too large. Please check the inflation \
                     parameters.",
                    *token
                );
                0u128
            })
    };
    let inflation_amount = Amount::from_uint(
        checked!(
            rewardable_tokens_in_masp.raw_amount() / precision.into()
                * Uint::from(noterized_inflation)
        )?,
        0,
    )
    .unwrap();
    let denom_amount = DenominatedAmount::new(inflation_amount, denomination);
    tracing::info!("MASP inflation for {token} is {denom_amount}");

    tracing::debug!(
        "Controller, call: total_in_masp {:?}, total_native_tokens {:?}, \
         locked_target_amount {:?}, last_locked_amount {:?}, max_reward_rate \
         {:?}, last_inflation {:?}, kp_gain_nom {:?}, kd_gain_nom {:?}, \
         epochs_per_year {:?}",
        total_tokens_in_masp,
        total_native_tokens,
        target_locked_amount,
        last_locked_amount,
        max_reward_rate,
        last_inflation,
        kp_gain_nom,
        kd_gain_nom,
        masp_epochs_per_year,
    );
    tracing::debug!("Token address: {:?}", token);
    tracing::debug!("inflation from the pd controller {:?}", inflation);
    tracing::debug!("total in the masp {:?}", total_tokens_in_masp);
    tracing::debug!("precision {}", precision);
    tracing::debug!("Noterized inflation: {}", noterized_inflation);

    // Is it fine to write the inflation rate, this is accurate,
    // but we should make sure the return value's ratio matches
    // this new inflation rate in 'update_allowed_conversions',
    // otherwise we will have an inaccurate view of inflation
    storage.write(
        &masp_last_inflation_key::<TransToken>(token),
        inflation_amount,
    )?;

    storage.write(
        &masp_last_locked_amount_key::<TransToken>(token),
        total_tokens_in_masp,
    )?;

    Ok((noterized_inflation, precision))
}

/// Update the conversions for native tokens. Namely calculate the reward using
/// the normed inflation as the denominator, make a 2-term allowed conversion,
/// and compute how much needs to be minted in order to back the rewards.
#[cfg(any(feature = "multicore", test))]
fn update_native_conversions<S, TransToken>(
    storage: &mut S,
    token: &Address,
    current_precision: &mut u128,
    masp_epochs_per_year: u64,
    masp_epoch: MaspEpoch,
    current_convs: &mut BTreeMap<
        (Address, Denomination, MaspDigitPos),
        AllowedConversion,
    >,
) -> Result<(Denomination, (u128, u128))>
where
    S: StorageWrite + StorageRead + WithConversionState,
    TransToken:
        trans_token::Keys + trans_token::Read<S> + trans_token::Write<S>,
{
    let prev_masp_epoch =
        masp_epoch.prev().ok_or_err_msg("MASP epoch underflow")?;
    let denom = TransToken::read_denom(storage, token)?
        .expect("failed to read token denomination");
    let (reward, _precision) = calculate_masp_rewards::<S, TransToken>(
        storage,
        token,
        denom,
        *current_precision,
        masp_epochs_per_year,
    )?;
    // The amount that will be given of the new native token for
    // every amount of the native token given in the
    // previous epoch
    let current_precision_uint = Uint::from(*current_precision);
    let reward = Uint::from(reward);
    let new_precision = checked!(current_precision_uint + reward)?;
    let new_precision = u128::try_from(new_precision).unwrap_or_else(|_| {
        tracing::warn!(
            "MASP precision for the native token {} is kept the same as in \
             the last epoch because the computed value is too large. Please \
             check the inflation parameters.",
            token
        );
        *current_precision
    });
    for digit in MaspDigitPos::iter() {
        // Provide an allowed conversion from previous timestamp. The
        // negative sign allows each instance of the old asset to be
        // cancelled out/replaced with the new asset
        let old_asset = encode_asset_type(
            token.clone(),
            denom,
            digit,
            Some(prev_masp_epoch),
        )
        .into_storage_result()?;
        let new_asset =
            encode_asset_type(token.clone(), denom, digit, Some(masp_epoch))
                .into_storage_result()?;
        // The conversion is computed such that if consecutive
        // conversions are added together, the intermediate native
        // tokens cancel/telescope out
        let cur_conv = MaspAmount::from_pair(
            old_asset,
            i128::try_from(*current_precision)
                .ok()
                .and_then(i128::checked_neg)
                .ok_or_err_msg("Current inflation overflow")?,
        );
        let new_conv = MaspAmount::from_pair(
            new_asset,
            i128::try_from(new_precision).into_storage_result()?,
        );
        current_convs.insert(
            (token.clone(), denom, digit),
            checked!(cur_conv + &new_conv)?.into(),
        );
        // Add a conversion from the previous asset type
        storage.conversion_state_mut().assets.insert(
            old_asset,
            ConversionLeaf {
                token: token.clone(),
                denom,
                digit_pos: digit,
                epoch: prev_masp_epoch,
                conversion: MaspAmount::zero().into(),
                leaf_pos: 0,
            },
        );
    }
    // Note the fraction used to compute rewards from balance
    let reward_frac = (
        new_precision
            .checked_sub(*current_precision)
            .unwrap_or_default(),
        *current_precision,
    );
    // Save the new native reward precision
    let reward_precision_key = masp_reward_precision_key::<TransToken>(token);
    storage.write(&reward_precision_key, new_precision)?;
    *current_precision = new_precision;
    Ok((denom, reward_frac))
}

/// Update the conversions for non-native tokens. Namely calculate the reward,
/// deflate it to real terms, make a 3-term allowed conversion, and compute how
/// much needs to be minted in order to back the rewards.
#[cfg(any(feature = "multicore", test))]
#[allow(clippy::too_many_arguments)]
fn update_non_native_conversions<S, TransToken>(
    storage: &mut S,
    token: &Address,
    base_native_precision: u128,
    current_native_precision: u128,
    masp_epochs_per_year: u64,
    masp_epoch: MaspEpoch,
    reward_assets: [AssetType; 4],
    total_reward: &mut Amount,
    current_convs: &mut BTreeMap<
        (Address, Denomination, MaspDigitPos),
        AllowedConversion,
    >,
) -> Result<Denomination>
where
    S: StorageWrite + StorageRead + WithConversionState,
    TransToken:
        trans_token::Keys + trans_token::Read<S> + trans_token::Write<S>,
{
    let prev_masp_epoch =
        masp_epoch.prev().ok_or_err_msg("MASP epoch underflow")?;
    let denom = TransToken::read_denom(storage, token)?
        .expect("failed to read token denomination");
    let precision =
        calculate_masp_rewards_precision::<S, TransToken>(storage, token)?;
    let (reward, precision) = calculate_masp_rewards::<S, TransToken>(
        storage,
        token,
        denom,
        precision,
        masp_epochs_per_year,
    )?;
    // Express the inflation reward in real terms, that is, with
    // respect to the native asset in the zeroth epoch
    let reward_uint = Uint::from(reward);
    let base_native_precision_uint = Uint::from(base_native_precision);
    let current_native_precision_uint = Uint::from(current_native_precision);
    let real_reward = checked!(
        (reward_uint * base_native_precision_uint)
            / current_native_precision_uint
    )?
    .try_into()
    .unwrap_or_else(|_| {
        tracing::warn!(
            "MASP reward for {} assumed to be 0 because the computed value is \
             too large. Please check the inflation parameters.",
            token
        );
        0u128
    });
    // The conversion is computed such that if consecutive
    // conversions are added together, the
    // intermediate tokens cancel/ telescope out
    let precision_i128 = i128::try_from(precision).into_storage_result()?;
    let real_reward_i128 = i128::try_from(real_reward).into_storage_result()?;
    for digit in MaspDigitPos::iter() {
        // Provide an allowed conversion from previous timestamp. The
        // negative sign allows each instance of the old asset to be
        // cancelled out/replaced with the new asset
        let old_asset = encode_asset_type(
            token.clone(),
            denom,
            digit,
            Some(prev_masp_epoch),
        )
        .into_storage_result()?;
        let new_asset =
            encode_asset_type(token.clone(), denom, digit, Some(masp_epoch))
                .into_storage_result()?;

        current_convs.insert(
            (token.clone(), denom, digit),
            checked!(
                MaspAmount::from_pair(old_asset, -precision_i128)
                    + &MaspAmount::from_pair(new_asset, precision_i128)
                    + &MaspAmount::from_pair(
                        reward_assets[digit as usize],
                        real_reward_i128,
                    )
            )?
            .into(),
        );
        // Add a conversion from the previous asset type
        storage.conversion_state_mut().assets.insert(
            old_asset,
            ConversionLeaf {
                token: token.clone(),
                denom,
                digit_pos: digit,
                epoch: prev_masp_epoch,
                conversion: MaspAmount::zero().into(),
                leaf_pos: 0,
            },
        );
    }
    // Dispense a transparent reward in parallel to the shielded rewards
    let addr_bal = get_masp_dated_balance::<S, TransToken>(storage, token)?;
    // The reward for each reward.1 units of the current asset
    // is reward.0 units of the reward token
    *total_reward = total_reward
        .checked_add(
            addr_bal
                .u128_eucl_div_rem((real_reward, precision))
                .ok_or_else(|| {
                    Error::new_const("Total reward calculation overflow")
                })?
                .0,
        )
        .ok_or_else(|| Error::new_const("Total reward overflow"))?;
    Ok(denom)
}

#[cfg(any(feature = "multicore", test))]
/// Apply the conversion updates that are in storage to the in memory structure
/// and delete them.
fn apply_stored_conversion_updates<S, TransToken>(
    storage: &mut S,
    ep: &MaspEpoch,
) -> Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
    TransToken:
        trans_token::Keys + trans_token::Read<S> + trans_token::Write<S>,
{
    // Read and apply any scheduled base native precisions
    let scheduled_base_precision_key =
        masp_scheduled_base_native_precision_key(ep);
    if let Some(precision) = storage.read(&scheduled_base_precision_key)? {
        let base_precision_key = masp_base_native_precision_key();
        storage.write::<Precision>(&base_precision_key, precision)?;
    }

    let scheduled_reward_precision_key_prefix =
        masp_scheduled_reward_precision_key_prefix(ep);
    let mut precision_updates = BTreeMap::<_, Precision>::new();
    // Read scheduled precisions from storage and store them in a map
    for prec_result in iter_prefix_with_filter_map(
        storage,
        scheduled_reward_precision_key_prefix.clone(),
        is_masp_scheduled_reward_precision_key,
    )? {
        match prec_result {
            Ok(((_ep, addr), precision)) => {
                precision_updates.insert(addr, precision);
            }
            Err(err) => {
                tracing::warn!("Encountered malformed precision: {}", err);
                continue;
            }
        }
    }
    // Apply the precision updates to storage
    for (addr, precision) in precision_updates {
        // Key to read/write reward precision from
        let reward_precision_key =
            masp_reward_precision_key::<TransToken>(&addr);
        storage.write(&reward_precision_key, precision)?;
    }
    let conversion_key_prefix = masp_conversion_key_prefix(ep);
    let mut conversion_updates =
        BTreeMap::<_, UncheckedAllowedConversion>::new();
    // Read conversion updates from storage and store them in a map
    for conv_result in iter_prefix_with_filter_map(
        storage,
        conversion_key_prefix.clone(),
        is_masp_conversion_key,
    )? {
        match conv_result {
            Ok(((_ep, asset_type), conv)) => {
                conversion_updates.insert(asset_type, conv);
            }
            Err(err) => {
                tracing::warn!("Encountered malformed conversion: {}", err);
                continue;
            }
        }
    }
    // Apply the conversion updates to the in memory structure
    let assets = &mut storage.conversion_state_mut().assets;
    for (asset_type, conv) in conversion_updates {
        let Some(leaf) = assets.get_mut(&asset_type) else {
            tracing::warn!(
                "Encountered non-existent asset type: {}",
                asset_type
            );
            continue;
        };
        leaf.conversion = conv.0;
    }
    // Delete the updates now that they have been applied
    storage.delete_prefix(&conversion_key_prefix)?;
    storage.delete_prefix(&scheduled_reward_precision_key_prefix)?;
    storage.delete(&scheduled_base_precision_key)?;
    Ok(())
}

#[cfg(any(feature = "multicore", test))]
/// Update the MASP's allowed conversions
pub fn update_allowed_conversions<S, Params, TransToken>(
    storage: &mut S,
) -> Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
    Params: parameters::Read<S>,
    TransToken:
        trans_token::Keys + trans_token::Read<S> + trans_token::Write<S>,
{
    use std::cmp::Ordering;

    use masp_primitives::bls12_381;
    use masp_primitives::ff::PrimeField;
    use masp_primitives::merkle_tree::FrozenCommitmentTree;
    use masp_primitives::sapling::Node;
    use namada_core::masp::encode_reward_asset_types;
    use namada_core::token::NATIVE_MAX_DECIMAL_PLACES;
    use rayon::iter::{
        IndexedParallelIterator, IntoParallelIterator, ParallelIterator,
    };
    use rayon::prelude::ParallelSlice;

    use crate::mint_rewards;

    // Get the previous MASP epoch if there's any
    let masp_epoch_multiplier = Params::masp_epoch_multiplier(storage)?;
    let masp_epoch = MaspEpoch::try_from_epoch(
        storage.get_block_epoch()?,
        masp_epoch_multiplier,
    )
    .map_err(Error::new_const)?;
    let Some(prev_masp_epoch) = masp_epoch.prev() else {
        return Ok(());
    };
    apply_stored_conversion_updates::<_, TransToken>(
        storage,
        &prev_masp_epoch,
    )?;
    let token_map_key = masp_token_map_key();
    let token_map: namada_core::masp::TokenMap =
        storage.read(&token_map_key)?.unwrap_or_default();
    let mut masp_reward_keys: Vec<_> = token_map.values().cloned().collect();
    let mut masp_reward_denoms = BTreeMap::new();
    // Put the native rewards first because other inflation computations depend
    // on it
    let native_token = storage.get_native_token()?;
    masp_reward_keys.sort_unstable_by(|x, y| {
        if (*x == native_token) == (*y == native_token) {
            Ordering::Equal
        } else if *x == native_token {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    });
    // The total transparent value of the rewards being distributed
    let mut total_deflated_reward = Amount::zero();

    let reward_assets =
        encode_reward_asset_types(&native_token).into_storage_result()?;
    // Conversions from the previous to current asset for each address
    let mut current_convs = BTreeMap::<
        (Address, Denomination, MaspDigitPos),
        AllowedConversion,
    >::new();
    // This is the base native token precision value
    let base_native_precision =
        read_base_native_precision::<_, TransToken>(storage, &native_token)?;
    // Get the last rewarded amount of the native token
    let mut current_native_precision = calculate_masp_rewards_precision::<
        S,
        TransToken,
    >(storage, &native_token)?;

    // Reward all tokens according to above reward rates
    let epochs_per_year = Params::epochs_per_year(storage)?;
    let masp_epochs_per_year =
        checked!(epochs_per_year / masp_epoch_multiplier)?;
    let mut native_reward_frac = None;
    for token in &masp_reward_keys {
        // Generate conversions from the last epoch to the current and update
        // the reward backing accumulator
        if *token == native_token {
            let (denom, frac) = update_native_conversions::<_, TransToken>(
                storage,
                token,
                &mut current_native_precision,
                masp_epochs_per_year,
                masp_epoch,
                &mut current_convs,
            )?;
            masp_reward_denoms.insert(token.clone(), denom);
            native_reward_frac = Some(frac);
        } else {
            let denom = update_non_native_conversions::<_, TransToken>(
                storage,
                token,
                base_native_precision,
                current_native_precision,
                masp_epochs_per_year,
                masp_epoch,
                reward_assets,
                &mut total_deflated_reward,
                &mut current_convs,
            )?;
            masp_reward_denoms.insert(token.clone(), denom);
        }
    }
    // Inflate the non-native rewards for all tokens in one operation
    let non_native_reward = total_deflated_reward
        .raw_amount()
        .checked_mul_div(
            current_native_precision.into(),
            base_native_precision.into(),
        )
        .ok_or_else(|| Error::new_const("Total reward calculation overflow"))?;
    // The total transparent value of the rewards being distributed. First
    // accumulate the integer part of the non-native reward.
    let mut total_reward = Amount::from(non_native_reward.0);
    // And finally accumulate the fractional parts of the native and non-native
    // rewards if their sum is more than one
    if let Some(native_reward_frac) = native_reward_frac {
        // Dispense a transparent reward in parallel to the shielded rewards
        let addr_bal = TransToken::read_balance(storage, &native_token, &MASP)?;
        // The reward for each reward.1 units of the current asset is reward.0
        // units of the reward token
        let native_reward = addr_bal
            .raw_amount()
            .checked_mul_div(
                native_reward_frac.0.into(),
                native_reward_frac.1.into(),
            )
            .ok_or_else(|| Error::new_const("Three digit reward overflow"))?;
        // Accumulate the integer part of the native reward
        checked!(total_reward += native_reward.0.into())?;

        let base_native_precision = Uint::from(base_native_precision);
        // Compute the fraction obtained by adding the fractional parts of the
        // native reward and the non-native reward:
        // native_reward.1/native_reward_frac.1 +
        // non_native_reward.1/base_native_precision
        let numerator = checked!(
            native_reward.1 * base_native_precision
                + Uint::from(native_reward_frac.1) * non_native_reward.1
        )?;
        let denominator =
            checked!(base_native_precision * Uint::from(native_reward_frac.1))?;
        // A fraction greater than or equal to one corresponds to the situation
        // where combining non-native rewards with pre-existing NAM balance
        // gives a greater reward than treating each separately.
        if numerator >= denominator {
            checked!(total_reward += 1.into())?;
        }
    }

    // Try to distribute Merkle leaf updating as evenly as possible across
    // multiple cores
    let num_threads = rayon::current_num_threads();
    // Put assets into vector to enable computation batching
    let assets: Vec<_> = storage
        .conversion_state_mut()
        .assets
        .values_mut()
        .enumerate()
        .collect();

    #[allow(clippy::arithmetic_side_effects)]
    let notes_per_thread_max = assets.len().div_ceil(num_threads);
    // floor(assets.len() / num_threads)
    #[allow(clippy::arithmetic_side_effects)]
    let notes_per_thread_min = assets.len() / num_threads;

    // Now on each core, add the latest conversion to each conversion
    let conv_notes: Vec<Node> = assets
        .into_par_iter()
        .with_min_len(notes_per_thread_min)
        .with_max_len(notes_per_thread_max)
        .map(|(idx, leaf)| {
            // Try to get the applicable conversion delta
            let cur_conv_key = (leaf.token.clone(), leaf.denom, leaf.digit_pos);
            if let Some(current_conv) = current_convs.get(&cur_conv_key) {
                // Use transitivity to update conversion
                #[allow(clippy::arithmetic_side_effects)]
                {
                    leaf.conversion += current_conv.clone();
                }
            }
            // Update conversion position to leaf we are about to create
            leaf.leaf_pos = idx;
            // The merkle tree need only provide the conversion commitment,
            // the remaining information is provided through the storage API
            Node::new(leaf.conversion.cmu().to_repr())
        })
        .collect();

    // Update the MASP's transparent reward token balance to ensure that it
    // is sufficiently backed to redeem rewards
    mint_rewards::<S, TransToken>(storage, total_reward)?;

    // Try to distribute Merkle tree construction as evenly as possible
    // across multiple cores
    // Merkle trees must have exactly 2^n leaves to be mergeable
    let mut notes_per_thread_rounded = 1;

    // Cannot overflow
    #[allow(clippy::arithmetic_side_effects)]
    while notes_per_thread_max > notes_per_thread_rounded * 4 {
        notes_per_thread_rounded *= 2;
    }
    // Make the sub-Merkle trees in parallel
    let tree_parts: Vec<_> = conv_notes
        .par_chunks(notes_per_thread_rounded)
        .map(FrozenCommitmentTree::new)
        .collect();

    // Convert conversion vector into tree so that Merkle paths can be
    // obtained
    storage.conversion_state_mut().tree =
        FrozenCommitmentTree::merge(&tree_parts);
    // Update the anchor in storage
    storage.write(
        &crate::storage_key::masp_convert_anchor_key(),
        namada_core::hash::Hash(
            bls12_381::Scalar::from(storage.conversion_state().tree.root())
                .to_bytes(),
        ),
    )?;

    if !masp_reward_keys.contains(&native_token) {
        // Since MASP rewards are denominated in NAM tokens, ensure that clients
        // are able to decode them.
        masp_reward_denoms
            .insert(native_token.clone(), NATIVE_MAX_DECIMAL_PLACES.into());
    }
    // Add purely decoding entries to the assets map. These will be
    // overwritten before the creation of the next commitment tree
    for (addr, denom) in masp_reward_denoms {
        for digit in MaspDigitPos::iter() {
            // Add the decoding entry for the new asset type. An uncommitted
            // node position is used since this is not a conversion.
            let new_asset =
                encode_asset_type(addr.clone(), denom, digit, Some(masp_epoch))
                    .into_storage_result()?;
            let tree_size = storage.conversion_state().tree.size();
            storage.conversion_state_mut().assets.insert(
                new_asset,
                ConversionLeaf {
                    token: addr.clone(),
                    denom,
                    digit_pos: digit,
                    epoch: masp_epoch,
                    conversion: MaspAmount::zero().into(),
                    leaf_pos: tree_size,
                },
            );
        }
    }
    // store only the assets hash because the size is quite large
    let assets_hash =
        Hash::sha256(storage.conversion_state().assets.serialize_to_vec());
    storage.write(&masp_assets_hash_key(), assets_hash)?;

    Ok(())
}

// This is only enabled when "wasm-runtime" is on, because we're using rayon
#[cfg(not(any(feature = "multicore", test)))]
/// Update the MASP's allowed conversions
pub fn update_allowed_conversions<S, Params, TransToken>(
    _storage: &mut S,
) -> Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
    Params: parameters::Read<S>,
    TransToken: trans_token::Keys,
{
    Ok(())
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use namada_core::address;
    use namada_core::collections::HashMap;
    use namada_core::dec::testing::arb_non_negative_dec;
    use namada_core::token::testing::arb_amount;
    use namada_state::testing::TestStorage;
    use namada_trans_token::storage_key::{balance_key, minted_balance_key};
    use namada_trans_token::write_denom;
    use proptest::prelude::*;
    use proptest::test_runner::Config;
    use test_log::test;

    use super::*;
    use crate::ShieldedParams;

    proptest! {
        #![proptest_config(Config {
            cases: 10,
            .. Config::default()
        })]
        #[test]
        fn test_updated_allowed_conversions(
            initial_balance in arb_amount(),
            masp_locked_ratio in arb_non_negative_dec(),
        ) {
            test_updated_allowed_conversions_aux(initial_balance, masp_locked_ratio)
        }
    }

    fn test_updated_allowed_conversions_aux(
        initial_balance: Amount,
        masp_locked_ratio: Dec,
    ) {
        const ROUNDS: usize = 10;

        let mut s = TestStorage::default();
        // Initialize the state
        {
            // Parameters
            namada_parameters::init_test_storage(&mut s).unwrap();

            // Tokens
            let token_params = ShieldedParams {
                max_reward_rate: Dec::from_str("0.1").unwrap(),
                kp_gain_nom: Dec::from_str("0.1").unwrap(),
                kd_gain_nom: Dec::from_str("0.1").unwrap(),
                locked_amount_target: 10_000_u64,
            };

            for (token_addr, (alias, denom)) in tokens() {
                namada_trans_token::write_params(&mut s, &token_addr).unwrap();
                crate::write_params::<_, namada_trans_token::Store<()>>(
                    &token_params,
                    &mut s,
                    &token_addr,
                    &denom,
                )
                .unwrap();

                write_denom(&mut s, &token_addr, denom).unwrap();

                // Write a minted token balance
                let total_token_balance = initial_balance;
                s.write(&minted_balance_key(&token_addr), total_token_balance)
                    .unwrap();

                // Put the locked ratio into MASP
                s.write(
                    &balance_key(&token_addr, &address::MASP),
                    masp_locked_ratio * total_token_balance,
                )
                .unwrap();

                // Insert tokens into MASP conversion state
                let token_map_key = masp_token_map_key();
                let mut token_map: namada_core::masp::TokenMap =
                    s.read(&token_map_key).unwrap().unwrap_or_default();
                token_map.insert(alias.to_string(), token_addr.clone());
                s.write(&token_map_key, token_map).unwrap();
            }
        }

        for i in 0..ROUNDS {
            println!("Round {i}");
            update_allowed_conversions::<
                _,
                namada_parameters::Store<_>,
                namada_trans_token::Store<_>,
            >(&mut s)
            .unwrap();
            println!();
            println!();
        }
    }

    pub fn tokens() -> HashMap<Address, (&'static str, Denomination)> {
        vec![
            (address::testing::nam(), ("nam", 6.into())),
            (address::testing::btc(), ("btc", 8.into())),
            (address::testing::eth(), ("eth", 18.into())),
            (address::testing::dot(), ("dot", 10.into())),
            (address::testing::schnitzel(), ("schnitzel", 6.into())),
            (address::testing::apfel(), ("apfel", 6.into())),
            (address::testing::kartoffel(), ("kartoffel", 6.into())),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn test_masp_inflation_playground() {
        let denom = Uint::from(1_000_000); // token denomination (usually 6)
        let total_tokens = 10_000_000_000_u64; // 10B naan
        let mut total_tokens = Uint::from(total_tokens) * denom;
        let locked_tokens_target = Uint::from(500_000) * denom; // Dependent on the token type
        let init_locked_ratio = Dec::from_str("0.1").unwrap(); // Arbitrary amount to play around with
        let init_locked_tokens = (init_locked_ratio
            * Dec::try_from(locked_tokens_target).unwrap())
        .to_uint()
        .unwrap();
        let epochs_per_year = 730_u64; // SE configuration
        let max_reward_rate = Dec::from_str("0.01").unwrap(); // Pre-determined based on token type
        let mut last_inflation_amount = Uint::zero();
        let p_gain_nom = Dec::from_str("25000").unwrap(); // To be configured
        let d_gain_nom = Dec::from_str("25000").unwrap(); // To be configured

        let mut locked_amount = init_locked_tokens;
        let mut locked_tokens_last = init_locked_tokens;

        let num_rounds = 10;
        println!();

        for round in 0..num_rounds {
            let inflation = compute_inflation(
                locked_amount,
                total_tokens,
                max_reward_rate,
                last_inflation_amount,
                p_gain_nom,
                d_gain_nom,
                epochs_per_year,
                Dec::try_from(locked_tokens_target).unwrap(),
                Dec::try_from(locked_tokens_last).unwrap(),
            );

            let rate = Dec::try_from(inflation).unwrap()
                * Dec::from(epochs_per_year)
                / Dec::try_from(total_tokens).unwrap();

            println!(
                "Round {round}: Locked amount: {locked_amount}, inflation \
                 rate: {rate} -- (raw infl: {inflation})",
            );
            // dbg!(&controller);

            last_inflation_amount = inflation;
            total_tokens += inflation;
            locked_tokens_last = locked_amount;

            let change_staked_tokens = Uint::from(2) * locked_tokens_target;
            locked_amount += change_staked_tokens;
        }
    }
}
