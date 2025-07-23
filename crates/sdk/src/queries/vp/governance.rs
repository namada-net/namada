// cd namada && cargo expand ledger::queries::vp::governance

use namada_governance::parameters::GovernanceParameters;
use namada_governance::storage::proposal::StorageProposal;
use namada_governance::utils::{ProposalResult, Vote};
use namada_state::{DBIter, DBRead, StorageHasher};

use crate::queries::types::RequestCtx;

// Governance queries
router! {GOV,
    ( "proposal" / [id: u64 ] ) -> Option<StorageProposal> = proposal_id,
    ( "proposal" / [id: u64 ] / "votes" ) -> Vec<Vote> = proposal_id_votes,
    ( "parameters" ) -> GovernanceParameters = parameters,
    ( "stored_proposal_result" / [id: u64] ) -> Option<ProposalResult> = proposal_result,
}

/// Query the provided proposal id
fn proposal_id<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    id: u64,
) -> namada_storage::Result<Option<StorageProposal>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::storage::get_proposal_by_id(ctx.state, id)
}

/// Query all the votes for the given proposal id
fn proposal_id_votes<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    id: u64,
) -> namada_storage::Result<Vec<Vote>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::storage::get_proposal_votes(ctx.state, id)
}

/// Get the governance parameters
fn parameters<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<GovernanceParameters>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::storage::get_parameters(ctx.state)
}

/// Get the governance proposal result stored in storage
fn proposal_result<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    id: u64,
) -> namada_storage::Result<Option<ProposalResult>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::storage::get_proposal_result(ctx.state, id)
}
