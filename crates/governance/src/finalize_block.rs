//! Governance logic applied on an end of a block.

use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use namada_core::address::Address;
use namada_core::chain::Epoch;
use namada_core::collections::HashMap;
use namada_core::encode;
use namada_core::ibc::PGFIbcTarget;
use namada_events::extend::{ComposeEvent, Height};
use namada_events::{EmitEvents, EventLevel};
use namada_state::{Key, Result, State, StateRead, StorageRead, StorageWrite};
use namada_systems::{proof_of_stake, trans_token as token};
use namada_tx::data::TxType;
use namada_tx::{Code, Data, Tx};

use crate::event::GovernanceEvent;
use crate::pgf::storage::keys as pgf_keys;
use crate::pgf::storage::steward::StewardDetail;
use crate::pgf::{ADDRESS as PGF_ADDRESS, storage as pgf_storage};
use crate::storage::proposal::{AddRemove, PGFAction, PGFTarget, ProposalType};
use crate::storage::{keys, load_proposals};
use crate::utils::{
    ProposalVotes, TallyResult, TallyType, VotePower, compute_proposal_result,
};
use crate::{ADDRESS as GOV_ADDRESS, ProposalVote, storage};

/// Apply governance updates for a block. On a new epoch, this will look for
/// proposals to tally completed proposals and execute accepted proposals.
#[allow(clippy::too_many_arguments)]
pub fn finalize_block<S, Token, PoS, FnTx, FnIbcTransfer>(
    state: &mut S,
    events: &mut impl EmitEvents,
    current_epoch: Epoch,
    is_new_epoch: bool,
    dispatch_tx: FnTx,
    transfer_over_ibc: FnIbcTransfer,
) -> Result<()>
where
    S: StateRead + State,
    Token: token::Read<S> + token::Write<S> + token::Events<S>,
    PoS: proof_of_stake::Read<S>,
    FnTx: FnMut(&Tx, &mut S) -> Result<bool>,
    FnIbcTransfer: Fn(&mut S, &Address, &Address, &PGFIbcTarget) -> Result<()>,
{
    if is_new_epoch {
        load_and_execute_governance_proposals::<
            S,
            Token,
            PoS,
            FnTx,
            FnIbcTransfer,
        >(state, events, current_epoch, dispatch_tx, transfer_over_ibc)?;
    }
    Ok(())
}

fn load_and_execute_governance_proposals<S, Token, PoS, FnTx, FnIbcTransfer>(
    state: &mut S,
    events: &mut impl EmitEvents,
    current_epoch: Epoch,
    dispatch_tx: FnTx,
    transfer_over_ibc: FnIbcTransfer,
) -> Result<()>
where
    S: StateRead + State,
    Token: token::Read<S> + token::Write<S> + token::Events<S>,
    PoS: proof_of_stake::Read<S>,
    FnTx: FnMut(&Tx, &mut S) -> Result<bool>,
    FnIbcTransfer: Fn(&mut S, &Address, &Address, &PGFIbcTarget) -> Result<()>,
{
    let proposal_ids = load_proposals(state, current_epoch)?;

    execute_governance_proposals::<S, Token, PoS, FnTx, FnIbcTransfer>(
        state,
        events,
        proposal_ids,
        dispatch_tx,
        transfer_over_ibc,
    )
}

fn execute_governance_proposals<S, Token, PoS, FnTx, FnIbcTransfer>(
    state: &mut S,
    events: &mut impl EmitEvents,
    proposal_ids: BTreeSet<u64>,
    mut dispatch_tx: FnTx,
    mut transfer_over_ibc: FnIbcTransfer,
) -> Result<()>
where
    S: StateRead + State,
    Token: token::Read<S> + token::Write<S> + token::Events<S>,
    PoS: proof_of_stake::Read<S>,
    FnTx: FnMut(&Tx, &mut S) -> Result<bool>,
    FnIbcTransfer: Fn(&mut S, &Address, &Address, &PGFIbcTarget) -> Result<()>,
{
    for id in proposal_ids {
        let proposal_funds_key = keys::get_funds_key(id);
        let proposal_end_epoch_key = keys::get_voting_end_epoch_key(id);
        let proposal_type_key = keys::get_proposal_type_key(id);
        let proposal_author_key = keys::get_author_key(id);

        let funds: token::Amount = force_read(state, &proposal_funds_key)?;
        let proposal_end_epoch: Epoch =
            force_read(state, &proposal_end_epoch_key)?;
        let proposal_type: ProposalType =
            force_read(state, &proposal_type_key)?;
        let proposal_author: Address = force_read(state, &proposal_author_key)?;

        let is_steward = pgf_storage::is_steward(state, &proposal_author)?;

        let total_active_voting_power = PoS::total_active_stake::<
            crate::Store<_>,
        >(state, proposal_end_epoch)?;

        let tally_type = TallyType::from(proposal_type.clone(), is_steward);
        let votes =
            compute_proposal_votes::<S, PoS>(state, id, proposal_end_epoch)?;
        let proposal_result = compute_proposal_result(
            votes,
            total_active_voting_power,
            tally_type,
        )
        .expect("Proposal result calculation must not over/underflow");
        storage::write_proposal_result(state, id, proposal_result)?;

        let transfer_address = match proposal_result.result {
            TallyResult::Passed => {
                let proposal_event = match proposal_type {
                    ProposalType::Default => {
                        tracing::info!(
                            "Governance proposal #{} (default) has passed.",
                            id,
                        );

                        GovernanceEvent::passed_proposal(id, false, false)
                    }
                    ProposalType::DefaultWithWasm(_) => {
                        let proposal_code =
                            storage::get_proposal_code(state, id)?
                                .unwrap_or_default();
                        let result = execute_default_proposal(
                            state,
                            id,
                            proposal_code.clone(),
                            &mut dispatch_tx,
                        )?;
                        tracing::info!(
                            "Governance proposal #{} (default with wasm) has \
                             passed and been executed, wasm execution: {}.",
                            id,
                            if result { "successful" } else { "unsuccessful" }
                        );

                        GovernanceEvent::passed_proposal(id, true, result)
                    }
                    ProposalType::PGFSteward(stewards) => {
                        let result =
                            execute_pgf_steward_proposal(state, stewards)?;
                        tracing::info!(
                            "Governance proposal #{} for PGF stewards has \
                             been executed. {}.",
                            id,
                            if result {
                                "State changes have been applied successfully"
                            } else {
                                "FAILURE trying to apply the state changes - \
                                 no state change occurred"
                            }
                        );

                        GovernanceEvent::passed_proposal(id, false, false)
                    }
                    ProposalType::PGFPayment(payments) => {
                        let native_token = state.get_native_token()?;
                        execute_pgf_funding_proposal::<S, Token, FnIbcTransfer>(
                            state,
                            &native_token,
                            payments,
                            id,
                            &mut transfer_over_ibc,
                        )?;
                        tracing::info!(
                            "Governance proposal #{} for PGF funding has \
                             passed and been executed.",
                            id
                        );

                        GovernanceEvent::passed_proposal(id, false, false)
                    }
                };
                events.emit(proposal_event);

                // Take events that could have been emitted by PGF
                // over IBC, governance proposal execution, etc
                let current_height =
                    state.in_mem().get_last_block_height().next_height();

                events.emit_many(
                    state
                        .write_log_mut()
                        .take_events()
                        .into_iter()
                        .map(|event| event.with(Height(current_height))),
                );

                storage::get_proposal_author(state, id)?
            }
            TallyResult::Rejected => {
                if let ProposalType::PGFPayment(_) = proposal_type {
                    if proposal_result.two_thirds_nay_over_two_thirds_total() {
                        pgf_storage::remove_steward(state, &proposal_author)?;

                        tracing::info!(
                            "Governance proposal {} was rejected with 2/3 of \
                             nay votes over 2/3 of the total voting power. If \
                             {} is a steward, it's being removed from the \
                             stewards set.",
                            id,
                            proposal_author
                        );
                    }
                }
                let proposal_event = GovernanceEvent::rejected_proposal(
                    id,
                    matches!(proposal_type, ProposalType::DefaultWithWasm(_)),
                );
                events.emit(proposal_event);

                tracing::info!(
                    "Governance proposal {} has been executed and rejected.",
                    id
                );

                None
            }
        };

        let native_token = state.get_native_token()?;
        if let Some(address) = transfer_address {
            Token::transfer(
                state,
                &native_token,
                &GOV_ADDRESS,
                &address,
                funds,
            )?;

            const DESCRIPTOR: &str = "governance-locked-funds-refund";

            Token::emit_transfer_event(
                state,
                DESCRIPTOR.into(),
                EventLevel::Tx,
                &native_token,
                funds,
                token::UserAccount::Internal(GOV_ADDRESS),
                token::UserAccount::Internal(address),
            )?;
        } else {
            Token::burn_tokens(state, &native_token, &GOV_ADDRESS, funds)?;

            const DESCRIPTOR: &str = "governance-locked-funds-burn";

            Token::emit_burn_event(
                state,
                DESCRIPTOR.into(),
                &native_token,
                funds,
                &GOV_ADDRESS,
            )?;
        }
    }
    Ok(())
}

fn compute_proposal_votes<S, PoS>(
    storage: &S,
    proposal_id: u64,
    epoch: Epoch,
) -> Result<ProposalVotes>
where
    S: StorageRead,
    PoS: proof_of_stake::Read<S>,
{
    let votes = storage::get_proposal_votes(storage, proposal_id)?;

    let mut validators_vote: HashMap<Address, ProposalVote> =
        HashMap::default();
    let mut validator_voting_power: HashMap<Address, VotePower> =
        HashMap::default();
    let mut delegators_vote: HashMap<Address, ProposalVote> =
        HashMap::default();
    let mut delegator_voting_power: HashMap<
        Address,
        HashMap<Address, VotePower>,
    > = HashMap::default();

    let mut validator_cache: HashMap<Address, bool> = HashMap::default();

    for vote in votes {
        let validator = &vote.validator;

        // Skip votes involving jailed or inactive validators
        let is_active_validator = if let Some(is_active_validator) =
            validator_cache.get(validator)
        {
            *is_active_validator
        } else {
            let is_active_validator = PoS::is_active_validator::<
                crate::Store<_>,
            >(storage, validator, epoch)?;
            validator_cache.insert(validator.clone(), is_active_validator);
            is_active_validator
        };
        if !is_active_validator {
            continue;
        }

        // Tally the votes involving active validators
        if vote.is_validator() {
            let vote_data = vote.data.clone();

            #[allow(clippy::disallowed_methods)]
            let validator_stake = PoS::read_validator_stake::<crate::Store<_>>(
                storage, validator, epoch,
            )
            .unwrap_or_default();

            validators_vote.insert(validator.clone(), vote_data);
            validator_voting_power.insert(validator.clone(), validator_stake);
        } else {
            let delegator = vote.delegator.clone();
            let vote_data = vote.data.clone();

            let delegator_stake = PoS::bond_amount::<crate::Store<_>>(
                storage, validator, &delegator, epoch,
            );

            if let Ok(stake) = delegator_stake {
                delegators_vote.insert(delegator.clone(), vote_data);
                delegator_voting_power
                    .entry(delegator)
                    .or_default()
                    .insert(validator.clone(), stake);
            } else {
                continue;
            }
        }
    }

    Ok(ProposalVotes {
        validators_vote,
        validator_voting_power,
        delegators_vote,
        delegator_voting_power,
    })
}

fn execute_default_proposal<S, FnTx>(
    state: &mut S,
    id: u64,
    proposal_code: Vec<u8>,
    dispatch_tx: &mut FnTx,
) -> Result<bool>
where
    S: StateRead + State,
    FnTx: FnMut(&Tx, &mut S) -> Result<bool>,
{
    let pending_execution_key = keys::get_proposal_execution_key(id);
    state.write(&pending_execution_key, ())?;

    let mut tx = Tx::from_type(TxType::Raw);
    tx.header.chain_id = state.get_chain_id()?;
    tx.set_data(Data::new(encode(&id)));
    tx.set_code(Code::new(proposal_code, None));

    let dispatch_result = dispatch_tx(&tx, state);
    state
        .delete(&pending_execution_key)
        .expect("Should be able to delete the storage.");
    dispatch_result
}

fn execute_pgf_steward_proposal<S>(
    storage: &mut S,
    stewards: BTreeSet<AddRemove<Address>>,
) -> Result<bool>
where
    S: StorageRead + StorageWrite,
{
    let maximum_number_of_pgf_steward_key =
        pgf_keys::get_maximum_number_of_pgf_steward_key();
    let maximum_number_of_pgf_steward = storage
        .read::<u64>(&maximum_number_of_pgf_steward_key)?
        .expect(
            "Pgf parameter maximum_number_of_pgf_steward must be in storage",
        );

    // First, remove the appropriate addresses
    for address in stewards.iter().filter_map(|action| match action {
        AddRemove::Add(_) => None,
        AddRemove::Remove(address) => Some(address),
    }) {
        pgf_keys::stewards_handle().remove(storage, address)?;
    }

    // Then add new addresses
    let mut steward_count = pgf_keys::stewards_handle().len(storage)?;
    for address in stewards.iter().filter_map(|action| match action {
        AddRemove::Add(address) => Some(address),
        AddRemove::Remove(_) => None,
    }) {
        #[allow(clippy::arithmetic_side_effects)]
        if steward_count + 1 > maximum_number_of_pgf_steward {
            return Ok(false);
        }
        pgf_keys::stewards_handle().insert(
            storage,
            address.to_owned(),
            StewardDetail::base(address.to_owned()),
        )?;

        #[allow(clippy::arithmetic_side_effects)]
        {
            steward_count += 1;
        }
    }

    Ok(true)
}

fn execute_pgf_funding_proposal<S, Token, FnIbcTransfer>(
    storage: &mut S,
    token: &Address,
    fundings: BTreeSet<PGFAction>,
    proposal_id: u64,
    transfer_over_ibc: &mut FnIbcTransfer,
) -> Result<bool>
where
    S: StorageRead + StorageWrite,
    Token: token::Write<S> + token::Events<S>,
    FnIbcTransfer: Fn(&mut S, &Address, &Address, &PGFIbcTarget) -> Result<()>,
{
    for funding in fundings {
        match funding {
            PGFAction::Continuous(action) => match action {
                AddRemove::Add(target) => {
                    tracing::info!(
                        "Adding Continuous PGF for {} from Proposal {} in the \
                         amount of {} per epoch, {}.",
                        target.target.target(),
                        proposal_id,
                        target.target.amount().to_string_native(),
                        if let Some(ep) = target.end_epoch {
                            format!("until epoch {}", ep)
                        } else {
                            "indefinitely".to_string()
                        }
                    );
                    pgf_keys::fundings_handle()
                        .at(&target.target.target())
                        .insert(storage, proposal_id, target.clone())?;
                }
                AddRemove::Remove(target) => {
                    tracing::info!(
                        "Removing Continuous PGF for {} from Proposal {} (set \
                         to {} native tokens, end epoch: {}).",
                        target.target.target(),
                        target.proposal_id,
                        target.target.amount().to_string_native(),
                        if let Some(ep) = target.end_epoch {
                            format!("{}", ep)
                        } else {
                            "None".to_string()
                        }
                    );
                    pgf_keys::fundings_handle()
                        .at(&target.target.target())
                        .remove(storage, &target.proposal_id)?;
                }
            },
            PGFAction::Retro(target) => {
                let result = match &target {
                    PGFTarget::Internal(target) => {
                        let result = Token::transfer(
                            storage,
                            token,
                            &PGF_ADDRESS,
                            &target.target,
                            target.amount,
                        );
                        if result.is_ok() {
                            Token::emit_transfer_event(
                                storage,
                                "pgf-payments".into(),
                                EventLevel::Block,
                                token,
                                target.amount,
                                token::UserAccount::Internal(PGF_ADDRESS),
                                token::UserAccount::Internal(
                                    target.target.clone(),
                                ),
                            )?;
                        }
                        result
                    }
                    PGFTarget::Ibc(target) => {
                        let result = transfer_over_ibc(
                            storage,
                            token,
                            &PGF_ADDRESS,
                            target,
                        );
                        if result.is_ok() {
                            Token::emit_transfer_event(
                                storage,
                                "pgf-payments-over-ibc".into(),
                                EventLevel::Block,
                                token,
                                target.amount,
                                token::UserAccount::Internal(PGF_ADDRESS),
                                token::UserAccount::External(
                                    target.target.clone(),
                                ),
                            )?;
                        }
                        result
                    }
                };
                match result {
                    Ok(()) => {
                        tracing::info!(
                            "Execute Retroactive PGF from Proposal {}: {}  \
                             native tokens transferred to {}.",
                            proposal_id,
                            target.amount().to_string_native(),
                            target.target()
                        );
                    }
                    Err(e) => tracing::warn!(
                        "Error in Retroactive PGF transfer from Proposal {}, \
                         attempt to transfer {} native tokens to {}: {}",
                        proposal_id,
                        target.amount().to_string_native(),
                        target.target(),
                        e
                    ),
                }
            }
        }
    }

    Ok(true)
}

fn force_read<S, T>(storage: &S, key: &Key) -> Result<T>
where
    S: StorageRead,
    T: BorshDeserialize,
{
    storage
        .read::<T>(key)
        .transpose()
        .expect("Storage key must be present.")
}
