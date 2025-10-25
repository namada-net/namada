//! PGF lib code.

use namada_core::address::Address;
use namada_state::{Result, StorageRead, StorageWrite};
use namada_systems::{parameters, trans_token};

use crate::pgf::storage::keys::fundings_handle;
use crate::pgf::storage::{
    get_continuous_pgf_payments, get_parameters, get_stewards,
};
use crate::storage::proposal::{PGFIbcTarget, PGFTarget};

fn remove_cpgf_target<S>(
    storage: &mut S,
    id: &u64,
    target_address: &String,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    fundings_handle().at(target_address).remove(storage, id)?;
    Ok(())
}

/// Apply the PGF inflation. Also
pub fn apply_inflation<S, Params, TransToken, F>(
    storage: &mut S,
    transfer_over_ibc: F,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
    Params: parameters::Read<S>,
    TransToken: trans_token::Read<S> + trans_token::Write<S>,
    F: Fn(&mut S, &Address, &Address, &PGFIbcTarget) -> Result<()>,
{
    let pgf_parameters = get_parameters(storage)?;
    let staking_token = storage.get_native_token()?;

    let epochs_per_year = Params::epochs_per_year(storage)?;
    let total_supply = TransToken::get_effective_total_native_supply(storage)?;

    // Mint tokens into the PGF address
    let pgf_inflation_amount = total_supply
        .mul_floor(pgf_parameters.pgf_inflation_rate)?
        .checked_div_u64(epochs_per_year)
        .unwrap_or_default();

    TransToken::credit_tokens(
        storage,
        &staking_token,
        &super::ADDRESS,
        pgf_inflation_amount,
    )?;

    tracing::info!(
        "Minting {} native tokens for PGF rewards distribution into the PGF \
         account (total supply: {}).",
        pgf_inflation_amount.to_string_native(),
        total_supply.to_string_native()
    );

    // TODO: make sure this is still sorted prioritizing older proposals
    let pgf_fundings = get_continuous_pgf_payments(storage)?;

    let current_epoch = storage.get_block_epoch()?;

    // Act on the continuous PGF fundings in storage: either distribute or
    // remove expired ones
    for (str_target_address, targets) in pgf_fundings {
        for (proposal_id, c_target) in targets {
            // Remove expired fundings from storage
            if c_target.is_expired(current_epoch) {
                remove_cpgf_target(storage, &proposal_id, &str_target_address)?;
                continue;
            }

            // Transfer PGF payment to target
            let result = match &c_target.target {
                PGFTarget::Internal(target) => TransToken::transfer(
                    storage,
                    &staking_token,
                    &super::ADDRESS,
                    &target.target,
                    target.amount,
                ),
                PGFTarget::Ibc(target) => transfer_over_ibc(
                    storage,
                    &staking_token,
                    &super::ADDRESS,
                    target,
                ),
            };
            match result {
                // TODO: not hardcode "NAM" below??
                Ok(()) => {
                    tracing::info!(
                        "Successfully transferred CPGF payment of {} NAM to \
                         {}.",
                        c_target.amount().to_string_native(),
                        &c_target.target(),
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        "Failed to transfer CPGF payment of {} NAM to {}.",
                        c_target.amount().to_string_native(),
                        &c_target.target(),
                    );
                }
            }
        }
    }

    // PGF steward inflation
    let stewards = get_stewards(storage)?;
    let pgf_steward_inflation = total_supply
        .mul_floor(pgf_parameters.stewards_inflation_rate)?
        .checked_div_u64(epochs_per_year)
        .unwrap_or_default();

    for steward in stewards {
        for (address, percentage) in steward.reward_distribution {
            let pgf_steward_reward =
                pgf_steward_inflation.mul_floor(percentage)?;

            if TransToken::credit_tokens(
                storage,
                &staking_token,
                &address,
                pgf_steward_reward,
            )
            .is_ok()
            {
                tracing::info!(
                    "Minting {} native tokens for steward {} (total supply: \
                     {})..",
                    pgf_steward_reward.to_string_native(),
                    address,
                    total_supply.to_string_native()
                );
            } else {
                tracing::warn!(
                    "Failed minting {} native tokens for steward {} (total \
                     supply: {})..",
                    pgf_steward_reward.to_string_native(),
                    address,
                    total_supply.to_string_native()
                );
            }
        }
    }

    Ok(())
}
