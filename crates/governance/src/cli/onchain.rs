use std::collections::BTreeMap;
use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::address::Address;
use namada_core::chain::Epoch;
use namada_core::token;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

use super::validation::{
    ProposalValidation, is_valid_activation_epoch, is_valid_author_balance,
    is_valid_content, is_valid_default_proposal_data, is_valid_end_epoch,
    is_valid_pgf_funding_data, is_valid_pgf_stewards_data,
    is_valid_proposal_period, is_valid_start_epoch,
};
use crate::parameters::GovernanceParameters;
use crate::storage::proposal::{ContPGFTarget, PGFTarget};

#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
/// The proposal structure
pub struct OnChainProposal {
    /// The proposal content
    pub content: BTreeMap<String, String>,
    /// The proposal author address
    pub author: Address,
    /// The epoch in which voting begins
    pub voting_start_epoch: Epoch,
    /// The final epoch in which voting is allowed
    pub voting_end_epoch: Epoch,
    /// The epoch in which any changes are executed and become active
    pub activation_epoch: Epoch,
}

/// PGF default proposal
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct DefaultProposal {
    /// The proposal data
    pub proposal: OnChainProposal,
    /// The default proposal extra data
    pub data: Option<Vec<u8>>,
}

impl DefaultProposal {
    /// Validate a default funding proposal
    pub fn validate(
        self,
        governance_parameters: &GovernanceParameters,
        current_epoch: Epoch,
        balance: token::Amount,
        force: bool,
    ) -> Result<Self, ProposalValidation> {
        if force {
            return Ok(self);
        }
        is_valid_start_epoch(self.proposal.voting_start_epoch, current_epoch)?;
        is_valid_end_epoch(
            self.proposal.voting_start_epoch,
            self.proposal.voting_end_epoch,
            current_epoch,
            governance_parameters.min_proposal_voting_period,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_activation_epoch(
            self.proposal.activation_epoch,
            self.proposal.voting_end_epoch,
            governance_parameters.min_proposal_grace_epochs,
        )?;
        is_valid_proposal_period(
            self.proposal.voting_start_epoch,
            self.proposal.activation_epoch,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_author_balance(
            balance,
            governance_parameters.min_proposal_fund,
        )?;
        is_valid_content(
            &self.proposal.content,
            governance_parameters.max_proposal_content_size,
        )?;
        is_valid_default_proposal_data(
            &self.data,
            governance_parameters.max_proposal_code_size,
        )?;

        Ok(self)
    }
}

impl TryFrom<&[u8]> for DefaultProposal {
    type Error = serde_json::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value)
    }
}

/// PGF stewards proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgfStewardProposal {
    /// The proposal data
    pub proposal: OnChainProposal,
    /// The PGF steward proposal extra data
    pub data: StewardsUpdate,
}

/// PGF steward proposal extra data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StewardsUpdate {
    /// The optional steward to add
    pub add: Option<Address>,
    /// The stewards to remove
    pub remove: Vec<Address>,
}

impl PgfStewardProposal {
    /// Validate a PGF stewards proposal
    pub fn validate(
        self,
        governance_parameters: &GovernanceParameters,
        current_epoch: Epoch,
        balance: token::Amount,
        force: bool,
    ) -> Result<Self, ProposalValidation> {
        if force {
            return Ok(self);
        }
        is_valid_start_epoch(self.proposal.voting_start_epoch, current_epoch)?;
        is_valid_end_epoch(
            self.proposal.voting_start_epoch,
            self.proposal.voting_end_epoch,
            current_epoch,
            governance_parameters.min_proposal_voting_period,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_activation_epoch(
            self.proposal.activation_epoch,
            self.proposal.voting_end_epoch,
            governance_parameters.min_proposal_grace_epochs,
        )?;
        is_valid_proposal_period(
            self.proposal.voting_start_epoch,
            self.proposal.activation_epoch,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_author_balance(
            balance,
            governance_parameters.min_proposal_fund,
        )?;
        is_valid_content(
            &self.proposal.content,
            governance_parameters.max_proposal_content_size,
        )?;
        is_valid_pgf_stewards_data(&self.data, &self.proposal.author)?;

        Ok(self)
    }
}

impl TryFrom<&[u8]> for PgfStewardProposal {
    type Error = serde_json::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value)
    }
}

/// PGF funding proposal
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct PgfFundingProposal {
    /// The proposal data
    pub proposal: OnChainProposal,
    /// The PGF funding proposal extra data
    pub data: PgfFunding,
}

impl PgfFundingProposal {
    /// Validate a PGF funding proposal
    pub fn validate(
        self,
        governance_parameters: &GovernanceParameters,
        current_epoch: Epoch,
        force: bool,
    ) -> Result<Self, ProposalValidation> {
        if force {
            return Ok(self);
        }
        is_valid_start_epoch(self.proposal.voting_start_epoch, current_epoch)?;
        is_valid_end_epoch(
            self.proposal.voting_start_epoch,
            self.proposal.voting_end_epoch,
            current_epoch,
            governance_parameters.min_proposal_voting_period,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_activation_epoch(
            self.proposal.activation_epoch,
            self.proposal.voting_end_epoch,
            governance_parameters.min_proposal_grace_epochs,
        )?;
        is_valid_proposal_period(
            self.proposal.voting_start_epoch,
            self.proposal.activation_epoch,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_content(
            &self.proposal.content,
            governance_parameters.max_proposal_content_size,
        )?;
        is_valid_pgf_funding_data(&self.data)?;

        Ok(self)
    }
}

impl TryFrom<&[u8]> for PgfFundingProposal {
    type Error = serde_json::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value)
    }
}

/// PGF stewards
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct PgfSteward {
    /// PGF action
    pub action: PgfAction,
    /// steward address
    pub address: Address,
}

/// PGF action
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub enum PgfAction {
    /// Add action
    Add,
    /// Remove action
    Remove,
}

impl PgfAction {
    /// Check if a PGF action is adding a steward
    pub fn is_add(&self) -> bool {
        matches!(self, PgfAction::Add)
    }
}

impl Display for PgfAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PgfAction::Add => write!(f, "Add"),
            PgfAction::Remove => write!(f, "Remove"),
        }
    }
}

/// PGF funding
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct PgfFunding {
    /// PGF continuous funding
    pub continuous: Vec<PgfContinuous>,
    /// PGF retro fundings
    pub retro: Vec<PGFTarget>,
}

impl Display for PgfFunding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.continuous.is_empty() {
            write!(f, "Continuous: ")?;
            for target in &self.continuous {
                write!(f, "  {}", &target)?;
            }
        }
        if !self.retro.is_empty() {
            write!(f, "Retro: ")?;
            for target in &self.retro {
                write!(f, "  {}", &target)?;
            }
        }
        Ok(())
    }
}

/// PGF continuous funding
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct PgfContinuous {
    /// PGF target
    pub target: ContPGFTarget,
    /// PGF action
    pub action: PgfAction,
}

impl Display for PgfContinuous {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\n{}:\n{}", &self.action, &self.target)
    }
}

/// PGF retro funding
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct PgfRetro {
    /// PGF retro target
    pub target: PGFTarget,
}
