use namada_core::address::{self, Address};
use namada_core::arith::checked;
use namada_core::masp::TokenMap;
use namada_core::token;
use namada_core::token::Amount;
use namada_core::uint::Uint;
use namada_systems::trans_token;

use crate::storage_key::*;
use crate::{Result, ResultExt, ShieldedParams, StorageRead, StorageWrite};

/// Initialize parameters for the token in storage during the genesis block.
pub fn write_params<S, TransToken>(
    params: &ShieldedParams,
    storage: &mut S,
    token: &Address,
    denom: &token::Denomination,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
    TransToken: trans_token::Keys,
{
    let ShieldedParams {
        max_reward_rate: max_rate,
        kd_gain_nom,
        kp_gain_nom,
        locked_amount_target,
    } = params;
    storage.write(
        &masp_last_inflation_key::<TransToken>(token),
        Amount::zero(),
    )?;
    storage.write(
        &masp_last_locked_amount_key::<TransToken>(token),
        Amount::zero(),
    )?;
    storage.write(&masp_max_reward_rate_key::<TransToken>(token), max_rate)?;
    storage.write(&masp_kp_gain_key::<TransToken>(token), kp_gain_nom)?;
    storage.write(&masp_kd_gain_key::<TransToken>(token), kd_gain_nom)?;

    let locked_amount_target = Uint::from(*locked_amount_target);
    let raw_target = checked!(
        locked_amount_target * (Uint::from(10) ^ Uint::from(denom.0))
    )?;
    let raw_target = Amount::from_uint(raw_target, 0).into_storage_result()?;
    storage.write(
        &masp_locked_amount_target_key::<TransToken>(token),
        raw_target,
    )?;
    Ok(())
}

/// Mint MASP rewards tokens and increment the stored total rewards.
pub fn mint_rewards<S, TransToken>(
    storage: &mut S,
    amount: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
    TransToken: trans_token::Write<S>,
{
    let native_token = storage.get_native_token()?;
    TransToken::credit_tokens(storage, &native_token, &address::MASP, amount)?;

    let total_rewards_key = masp_total_rewards();
    let mut total_rewards = read_total_rewards(storage)?;
    checked!(total_rewards += amount)?;
    storage.write(&total_rewards_key, total_rewards)
}

/// Read the total rewards minted by MASP.
pub fn read_total_rewards<S>(storage: &S) -> Result<token::Amount>
where
    S: StorageRead,
{
    let total_rewards_key = masp_total_rewards();
    let total_rewards: token::Amount =
        storage.read(&total_rewards_key)?.unwrap_or_default();
    Ok(total_rewards)
}

/// Read the undated balance of the given token in the MASP.
pub fn read_undated_balance<S>(
    storage: &S,
    token_address: &Address,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    let undated_balance_key = masp_undated_balance_key(token_address);
    let undated_balance: token::Amount =
        storage.read(&undated_balance_key)?.unwrap_or_default();
    Ok(undated_balance)
}

/// Write the undated balance of the given token in the MASP.
pub fn write_undated_balance<S>(
    storage: &mut S,
    token_address: &Address,
    balance: token::Amount,
) -> Result<()>
where
    S: StorageWrite,
{
    let undated_balance_key = masp_undated_balance_key(token_address);
    storage.write(&undated_balance_key, balance)
}

/// Read the masp token map.
pub fn read_token_map<S>(storage: &S) -> Result<TokenMap>
where
    S: StorageRead,
{
    let token_map_key = masp_token_map_key();
    Ok(storage.read(&token_map_key)?.unwrap_or_default())
}

/// Write a new masp token map.
pub fn write_token_map<S>(storage: &mut S, token_map: TokenMap) -> Result<()>
where
    S: StorageWrite,
{
    let token_map_key = masp_token_map_key();
    storage.write(&token_map_key, token_map)
}
