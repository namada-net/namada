//! Pgf

/// Pgf storage keys
pub mod keys;
/// Pgf steward structures
pub mod steward;

use namada_core::address::Address;
use namada_core::collections::HashMap;
use namada_core::dec::Dec;
use namada_state::collections::lazy_map::Collectable;
use namada_state::{Result, StorageRead, StorageWrite};

use crate::pgf::parameters::PgfParameters;
use crate::pgf::storage::keys as pgf_keys;
use crate::pgf::storage::steward::StewardDetail;
use crate::storage::proposal::ContPgfFundings;

/// Query the current pgf steward set
pub fn get_stewards<S>(storage: &S) -> Result<Vec<StewardDetail>>
where
    S: StorageRead,
{
    let stewards = pgf_keys::stewards_handle()
        .iter(storage)?
        .filter_map(|data| match data {
            Ok((_, steward)) => Some(steward),
            Err(_) => None,
        })
        .collect::<Vec<StewardDetail>>();

    Ok(stewards)
}

/// Query the a steward by address
pub fn get_steward<S>(
    storage: &S,
    address: &Address,
) -> Result<Option<StewardDetail>>
where
    S: StorageRead,
{
    pgf_keys::stewards_handle().get(storage, address)
}

/// Check if an address is a steward
pub fn is_steward<S>(storage: &S, address: &Address) -> Result<bool>
where
    S: StorageRead,
{
    pgf_keys::stewards_handle().contains(storage, address)
}

/// Remove a steward
pub fn remove_steward<S>(storage: &mut S, address: &Address) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    pgf_keys::stewards_handle().remove(storage, address)?;

    Ok(())
}

/// Query the current pgf continuous payments
pub fn get_continuous_pgf_payments<S>(storage: &S) -> Result<ContPgfFundings>
where
    S: StorageRead,
{
    let fundings = pgf_keys::fundings_handle().collect_map(storage)?;
    Ok(fundings)
}

/// Query the pgf parameters
pub fn get_parameters<S>(storage: &S) -> Result<PgfParameters>
where
    S: StorageRead,
{
    let pgf_inflation_rate_key = pgf_keys::get_pgf_inflation_rate_key();
    let stewards_inflation_rate_key =
        pgf_keys::get_steward_inflation_rate_key();

    let pgf_inflation_rate: Dec = storage
        .read(&pgf_inflation_rate_key)?
        .expect("Parameter should be defined.");
    let stewards_inflation_rate: Dec = storage
        .read(&stewards_inflation_rate_key)?
        .expect("Parameter should be defined.");

    Ok(PgfParameters {
        pgf_inflation_rate,
        stewards_inflation_rate,
        ..Default::default()
    })
}

/// Update the commission for a steward
pub fn update_commission<S>(
    storage: &mut S,
    address: Address,
    reward_distribution: HashMap<Address, Dec>,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    pgf_keys::stewards_handle().insert(
        storage,
        address.clone(),
        StewardDetail {
            address,
            reward_distribution,
        },
    )?;

    Ok(())
}
