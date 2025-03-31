//! Governance storage

/// Governance proposal keys
pub mod keys;
/// Proposal structures
pub mod proposal;
/// Vote structures
pub mod vote;

use std::collections::{BTreeMap, BTreeSet};

use namada_core::address::Address;
use namada_core::borsh::BorshDeserialize;
use namada_core::chain::Epoch;
use namada_core::collections::HashSet;
use namada_core::hash::Hash;
use namada_core::token;
use namada_state::{Error, Result, StorageRead, StorageWrite, iter_prefix};
use namada_systems::trans_token;

use crate::ADDRESS as governance_address;
use crate::parameters::GovernanceParameters;
use crate::storage::keys as governance_keys;
use crate::storage::proposal::{
    InitProposalData, ProposalType, StorageProposal, VoteProposalData,
};
use crate::storage::vote::ProposalVote;
use crate::utils::{ProposalResult, Vote};

/// A proposal creation transaction.
pub fn init_proposal<S, TransToken>(
    storage: &mut S,
    data: &InitProposalData,
    content: Vec<u8>,
    code: Option<Vec<u8>>,
) -> Result<u64>
where
    S: StorageRead + StorageWrite,
    TransToken: trans_token::Write<S>,
{
    let counter_key = governance_keys::get_counter_key();
    let proposal_id = storage.read(&counter_key)?.expect(
        "Storage should have been initialized with an initial governance \
         proposal id",
    );

    let content_key = governance_keys::get_content_key(proposal_id);
    // The content should have been already encoded with borsh
    storage.write_bytes(&content_key, content)?;

    let author_key = governance_keys::get_author_key(proposal_id);
    storage.write(&author_key, data.author.clone())?;

    let proposal_type_key = governance_keys::get_proposal_type_key(proposal_id);
    match data.r#type {
        ProposalType::DefaultWithWasm(_) => {
            storage.write(&proposal_type_key, data.r#type.clone())?;
            let proposal_code_key =
                governance_keys::get_proposal_code_key(proposal_id);

            let proposal_code =
                code.ok_or(Error::new_const("Missing proposal code"))?;
            storage.write(&proposal_code_key, proposal_code)?;
        }
        _ => storage.write(&proposal_type_key, data.r#type.clone())?,
    }

    let voting_start_epoch_key =
        governance_keys::get_voting_start_epoch_key(proposal_id);
    storage.write(&voting_start_epoch_key, data.voting_start_epoch)?;

    let voting_end_epoch_key =
        governance_keys::get_voting_end_epoch_key(proposal_id);
    storage.write(&voting_end_epoch_key, data.voting_end_epoch)?;

    let activation_epoch_key =
        governance_keys::get_activation_epoch_key(proposal_id);
    storage.write(&activation_epoch_key, data.activation_epoch)?;

    storage.write(
        &counter_key,
        proposal_id
            .checked_add(1)
            .expect("Number of proposals should never exceed `u64::MAX`"),
    )?;

    let min_proposal_funds_key = governance_keys::get_min_proposal_fund_key();
    let min_proposal_funds: token::Amount =
        storage.read(&min_proposal_funds_key)?.unwrap();

    let funds_key = governance_keys::get_funds_key(proposal_id);
    storage.write(&funds_key, min_proposal_funds)?;

    // this key must always be written for each proposal
    let committing_proposals_key =
        governance_keys::get_committing_proposals_key(
            proposal_id,
            data.activation_epoch.0,
        );
    storage.write(&committing_proposals_key, ())?;

    TransToken::transfer(
        storage,
        &storage.get_native_token()?,
        &data.author,
        &governance_address,
        min_proposal_funds,
    )?;

    Ok(proposal_id)
}

/// A proposal vote transaction.
pub fn vote_proposal<S>(
    storage: &mut S,
    data: VoteProposalData,
    delegation_targets: HashSet<Address>,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    for validator in delegation_targets {
        let vote_key = governance_keys::get_vote_proposal_key(
            data.id,
            data.voter.clone(),
            validator,
        );
        storage.write(&vote_key, data.vote.clone())?;
    }
    Ok(())
}

/// Write the proposal result to storage.
pub fn write_proposal_result<S>(
    storage: &mut S,
    proposal_id: u64,
    proposal_result: ProposalResult,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let proposal_result_key =
        governance_keys::get_proposal_result_key(proposal_id);
    storage.write(&proposal_result_key, proposal_result)
}

/// Read a proposal by id from storage
pub fn get_proposal_by_id<S>(
    storage: &S,
    id: u64,
) -> Result<Option<StorageProposal>>
where
    S: StorageRead,
{
    let author_key = governance_keys::get_author_key(id);
    let content = governance_keys::get_content_key(id);
    let start_epoch_key = governance_keys::get_voting_start_epoch_key(id);
    let end_epoch_key = governance_keys::get_voting_end_epoch_key(id);
    let activation_epoch_key = governance_keys::get_activation_epoch_key(id);
    let proposal_type_key = governance_keys::get_proposal_type_key(id);

    let author: Option<Address> = storage.read(&author_key)?;
    let content: Option<BTreeMap<String, String>> = storage.read(&content)?;
    let voting_start_epoch: Option<Epoch> = storage.read(&start_epoch_key)?;
    let voting_end_epoch: Option<Epoch> = storage.read(&end_epoch_key)?;
    let activation_epoch: Option<Epoch> =
        storage.read(&activation_epoch_key)?;
    let proposal_type: Option<ProposalType> =
        storage.read(&proposal_type_key)?;

    let proposal_type = if let Some(proposal_type) = proposal_type {
        if let ProposalType::DefaultWithWasm(_) = proposal_type {
            let proposal_code_key = governance_keys::get_proposal_code_key(id);
            let proposal_code: Vec<u8> =
                storage.read(&proposal_code_key)?.unwrap_or_default();
            let proposal_code_hash = Hash::sha256(proposal_code);
            ProposalType::DefaultWithWasm(proposal_code_hash)
        } else {
            proposal_type
        }
    } else {
        return Ok(None);
    };

    Ok(Some(StorageProposal {
        id,
        content: content.unwrap(),
        author: author.unwrap(),
        r#type: proposal_type,
        voting_start_epoch: voting_start_epoch.unwrap(),
        voting_end_epoch: voting_end_epoch.unwrap(),
        activation_epoch: activation_epoch.unwrap(),
    }))
}

/// Query all the votes for a proposal_id
pub fn get_proposal_votes<S>(storage: &S, proposal_id: u64) -> Result<Vec<Vote>>
where
    S: StorageRead,
{
    let vote_prefix_key =
        governance_keys::get_proposal_vote_prefix_key(proposal_id);
    let vote_iter = iter_prefix::<ProposalVote>(storage, vote_prefix_key)?;

    let votes = vote_iter
        .filter_map(|vote_result| {
            if let Ok((vote_key, vote)) = vote_result {
                let voter_address =
                    governance_keys::get_voter_address(&vote_key);
                let delegator_address =
                    governance_keys::get_vote_delegation_address(&vote_key);
                match (voter_address, delegator_address) {
                    (Some(delegator_address), Some(validator_address)) => {
                        Some(Vote {
                            validator: validator_address.to_owned(),
                            delegator: delegator_address.to_owned(),
                            data: vote,
                        })
                    }
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect::<Vec<Vote>>();

    Ok(votes)
}

/// Check if an accepted proposal is being executed
pub fn is_proposal_accepted<S>(storage: &S, tx_data: &[u8]) -> Result<bool>
where
    S: StorageRead,
{
    let proposal_id = u64::try_from_slice(tx_data);
    if let Ok(id) = proposal_id {
        let proposal_execution_key =
            governance_keys::get_proposal_execution_key(id);
        storage.has_key(&proposal_execution_key)
    } else {
        Ok(false)
    }
}

/// Get the code associated with a proposal
pub fn get_proposal_code<S>(
    storage: &S,
    proposal_id: u64,
) -> Result<Option<Vec<u8>>>
where
    S: StorageRead,
{
    let proposal_code_key = governance_keys::get_proposal_code_key(proposal_id);
    storage.read(&proposal_code_key)
}

/// Get the code associated with a proposal
pub fn get_proposal_author<S>(
    storage: &S,
    proposal_id: u64,
) -> Result<Option<Address>>
where
    S: StorageRead,
{
    let proposal_author_key = governance_keys::get_author_key(proposal_id);
    storage.read::<Address>(&proposal_author_key)
}

/// Get governance parameters
pub fn get_parameters<S>(storage: &S) -> Result<GovernanceParameters>
where
    S: StorageRead,
{
    let key = governance_keys::get_max_proposal_code_size_key();
    let max_proposal_code_size: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");

    let key = governance_keys::get_max_proposal_content_key();
    let max_proposal_content_size: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");

    let key = governance_keys::get_min_proposal_fund_key();
    let min_proposal_fund: token::Amount =
        storage.read(&key)?.expect("Parameter should be defined.");

    let key = governance_keys::get_min_proposal_grace_epochs_key();
    let min_proposal_grace_epochs: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");

    let key = governance_keys::get_min_proposal_voting_period_key();
    let min_proposal_voting_period: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");

    let max_proposal_period: u64 = get_max_proposal_period(storage)?;

    let key = governance_keys::get_max_proposal_latency_key();
    let max_proposal_latency: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");

    Ok(GovernanceParameters {
        min_proposal_fund,
        max_proposal_code_size,
        min_proposal_voting_period,
        max_proposal_period,
        max_proposal_content_size,
        min_proposal_grace_epochs,
        max_proposal_latency,
    })
}

/// Get governance "max_proposal_period" parameter
pub fn get_max_proposal_period<S>(storage: &S) -> Result<u64>
where
    S: StorageRead,
{
    let key = governance_keys::get_max_proposal_period_key();
    let max_proposal_period: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");
    Ok(max_proposal_period)
}

/// Get governance proposal result stored in storage if proposal ended
pub fn get_proposal_result<S>(
    storage: &S,
    proposal_id: u64,
) -> Result<Option<ProposalResult>>
where
    S: StorageRead,
{
    let key = governance_keys::get_proposal_result_key(proposal_id);
    let proposal_result: Option<ProposalResult> = storage.read(&key)?;
    Ok(proposal_result)
}

/// Load proposals for execution in the current epoch.
pub fn load_proposals<S>(
    storage: &S,
    current_epoch: Epoch,
) -> Result<BTreeSet<u64>>
where
    S: StorageRead,
{
    let mut ids = BTreeSet::<u64>::new();
    let proposals_key =
        governance_keys::get_commiting_proposals_prefix(current_epoch.0);
    for key_val in namada_state::iter_prefix_bytes(storage, proposals_key)? {
        let (key, _) = key_val?;
        let activation_epoch = governance_keys::get_commit_proposal_epoch(&key)
            .expect("this key segment should correspond to an epoch number");
        if current_epoch.0 == activation_epoch {
            let proposal_id = governance_keys::get_commit_proposal_id(&key)
                .expect("ths key segment should correspond to a proposal id");
            ids.insert(proposal_id);
        }
    }

    Ok(ids)
}
