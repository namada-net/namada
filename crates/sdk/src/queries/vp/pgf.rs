use namada_core::address::Address;
use namada_governance::pgf::parameters::PgfParameters;
use namada_governance::pgf::storage::steward::StewardDetail;
use namada_governance::storage::proposal::ContPgfFundings;
use namada_state::{DB, DBIter, StorageHasher};

use crate::queries::types::RequestCtx;

// PoS validity predicate queries
router! {PGF,
    ( "stewards" / [ address: Address ] ) -> bool = is_steward,
    ( "stewards" ) -> Vec<StewardDetail> = stewards,
    ( "fundings" ) -> ContPgfFundings = funding,
    ( "parameters" ) -> PgfParameters = parameters,
}

/// Query the current pgf steward set
fn stewards<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<Vec<StewardDetail>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::pgf::storage::get_stewards(ctx.state)
}

/// Check if an address is a pgf steward
fn is_steward<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    address: Address,
) -> namada_storage::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::pgf::storage::is_steward(ctx.state, &address)
}

/// Query the continuous pgf fundings
fn funding<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<ContPgfFundings>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::pgf::storage::get_continuous_pgf_payments(ctx.state)
}

/// Query the PGF parameters
fn parameters<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<PgfParameters>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::pgf::storage::get_parameters(ctx.state)
}
