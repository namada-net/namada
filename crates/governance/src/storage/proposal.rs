use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use itertools::Itertools;
use namada_core::address::Address;
use namada_core::chain::Epoch;
use namada_core::hash::Hash;
pub use namada_core::ibc::PGFIbcTarget;
use namada_core::token;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::vote::ProposalVote;
use crate::cli::onchain::{
    DefaultProposal, PgfAction, PgfContinuous, PgfFundingProposal, PgfRetro,
    PgfSteward, PgfStewardProposal, StewardsUpdate,
};
use crate::utils::{ProposalStatus, TallyType};

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ProposalError {
    #[error("Invalid proposal data.")]
    InvalidProposalData,
}

/// A tx data type to hold proposal data
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSchema,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct InitProposalData {
    /// The proposal content
    pub content: Hash,
    /// The proposal author address
    pub author: Address,
    /// The proposal type
    pub r#type: ProposalType,
    /// The epoch in which voting begins
    pub voting_start_epoch: Epoch,
    /// The final epoch in which voting is allowed
    pub voting_end_epoch: Epoch,
    /// The epoch in which any changes are executed and become active
    pub activation_epoch: Epoch,
}

impl InitProposalData {
    /// Get the hash of the corresponding extra data section
    pub fn get_section_code_hash(&self) -> Option<Hash> {
        match self.r#type {
            ProposalType::DefaultWithWasm(hash) => Some(hash),
            _ => None,
        }
    }
}

/// A tx data type to hold vote proposal data
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSchema,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct VoteProposalData {
    /// The proposal id
    pub id: u64,
    /// The proposal vote
    pub vote: ProposalVote,
    /// The proposal voter address
    pub voter: Address,
}

impl TryFrom<DefaultProposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(value: DefaultProposal) -> Result<Self, Self::Error> {
        Ok(InitProposalData {
            content: Hash::default(),
            author: value.proposal.author,
            r#type: match value.data {
                Some(bytes) => {
                    if bytes.is_empty() {
                        ProposalType::Default
                    } else {
                        ProposalType::DefaultWithWasm(Hash::default())
                    }
                }
                None => ProposalType::Default,
            },
            voting_start_epoch: value.proposal.voting_start_epoch,
            voting_end_epoch: value.proposal.voting_end_epoch,
            activation_epoch: value.proposal.activation_epoch,
        })
    }
}

impl TryFrom<PgfStewardProposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(value: PgfStewardProposal) -> Result<Self, Self::Error> {
        let extra_data =
            BTreeSet::<AddRemove<Address>>::try_from(value.data).unwrap();

        Ok(InitProposalData {
            content: Hash::default(),
            author: value.proposal.author,
            r#type: ProposalType::PGFSteward(extra_data),
            voting_start_epoch: value.proposal.voting_start_epoch,
            voting_end_epoch: value.proposal.voting_end_epoch,
            activation_epoch: value.proposal.activation_epoch,
        })
    }
}

impl TryFrom<PgfFundingProposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(value: PgfFundingProposal) -> Result<Self, Self::Error> {
        let mut continuous_fundings = value
            .data
            .continuous
            .iter()
            .cloned()
            .map(|c_target| match c_target.action {
                PgfAction::Add => {
                    PGFAction::Continuous(AddRemove::Add(c_target.target))
                }
                PgfAction::Remove => {
                    PGFAction::Continuous(AddRemove::Remove(c_target.target))
                }
            })
            .collect::<BTreeSet<PGFAction>>();

        let retro_fundings = value
            .data
            .retro
            .iter()
            .cloned()
            .map(PGFAction::Retro)
            .collect::<BTreeSet<PGFAction>>();

        continuous_fundings.extend(retro_fundings);

        Ok(InitProposalData {
            content: Hash::default(),
            author: value.proposal.author,
            r#type: ProposalType::PGFPayment(continuous_fundings), /* here continuous_fundings also contains the retro funding */
            voting_start_epoch: value.proposal.voting_start_epoch,
            voting_end_epoch: value.proposal.voting_end_epoch,
            activation_epoch: value.proposal.activation_epoch,
        })
    }
}

/// Storage struture for pgf fundings
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct StoragePgfFunding {
    /// The data about the pgf funding
    pub detail: ContPGFTarget,
    /// The id of the proposal that added this funding
    pub id: u64,
}

impl StoragePgfFunding {
    /// Init a new pgf funding struct
    pub fn new(detail: ContPGFTarget, id: u64) -> Self {
        Self { detail, id }
    }
}

/// Sorted map of continuous pgf distributions
pub type ContPgfFundings = BTreeMap<String, BTreeMap<u64, ContPGFTarget>>;

/// The type of a Proposal
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSchema,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub enum ProposalType {
    /// Default governance proposal
    Default,
    /// Governance proposal with wasm code
    DefaultWithWasm(Hash),
    /// PGF stewards proposal
    PGFSteward(BTreeSet<AddRemove<Address>>),
    /// PGF funding proposal
    PGFPayment(BTreeSet<PGFAction>),
}

/// An add or remove action for PGF
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSchema,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub enum AddRemove<T> {
    /// Add
    Add(T),
    /// Remove
    Remove(T),
}

impl<T> Display for AddRemove<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddRemove::Add(address) => write!(f, "Add({})", &address),
            AddRemove::Remove(address) => write!(f, "Remove({})", &address),
        }
    }
}

/// The actions that yo momma can execute
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSchema,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
    Eq,
    Ord,
    PartialOrd,
    Hash,
)]
pub struct ContPGFTarget {
    /// PGF target
    pub target: PGFTarget,
    /// The epoch at which the funding ends, if any
    pub end_epoch: Option<Epoch>,
    /// The proposal ID that added this PGF payment
    pub proposal_id: u64,
}

impl Display for ContPGFTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.target.clone() {
            PGFTarget::Internal(t) => {
                write!(
                    f,
                    "Internal address={}, amount={}, end epoch = {}",
                    t.target,
                    t.amount,
                    if let Some(epoch) = self.end_epoch {
                        epoch.0.to_string()
                    } else {
                        String::from("None")
                    }
                )
            }
            PGFTarget::Ibc(t) => {
                write!(
                    f,
                    "IBC address={}, amount={}, end epoch = {}",
                    t.target,
                    t.amount,
                    if let Some(epoch) = self.end_epoch {
                        epoch.0.to_string()
                    } else {
                        String::from("None")
                    }
                )
            }
        }
    }
}

impl ContPGFTarget {
    /// Returns the funding target as String
    pub fn target(&self) -> String {
        self.target.target()
    }

    /// Returns the funding amount
    pub fn amount(&self) -> token::Amount {
        self.target.amount()
    }

    /// Check if the funding is expired
    pub fn is_expired(&self, current_epoch: Epoch) -> bool {
        if let Some(end_epoch) = self.end_epoch {
            current_epoch >= end_epoch
        } else {
            false
        }
    }
}

/// The target of a PGF payment
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSchema,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
    Ord,
    Eq,
    PartialOrd,
    Hash,
)]
pub enum PGFTarget {
    /// Funding target on this chain
    Internal(PGFInternalTarget),
    /// Funding target on another chain
    Ibc(PGFIbcTarget),
}

impl PGFTarget {
    /// Returns the funding target as String
    pub fn target(&self) -> String {
        match self {
            PGFTarget::Internal(t) => t.target.to_string(),
            PGFTarget::Ibc(t) => t.target.clone(),
        }
    }

    /// Returns the funding amount
    pub fn amount(&self) -> token::Amount {
        match self {
            PGFTarget::Internal(t) => t.amount,
            PGFTarget::Ibc(t) => t.amount,
        }
    }
}

impl Display for PGFTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PGFTarget::Internal(t) => {
                write!(f, "Internal address={}, amount={}", t.target, t.amount)
            }
            PGFTarget::Ibc(t) => {
                write!(f, "IBC address={}, amount={}", t.target, t.amount)
            }
        }
    }
}

/// The target of a PGF payment
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSchema,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
    Ord,
    Eq,
    PartialOrd,
    Hash,
)]
pub struct PGFInternalTarget {
    /// The target address
    pub target: Address,
    /// The amount of token to fund the target address
    pub amount: token::Amount,
}

/// The actions that a PGF Steward can propose to execute
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSchema,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
    Eq,
    Ord,
    PartialOrd,
    Hash,
)]
pub enum PGFAction {
    /// A continuous payment
    Continuous(AddRemove<ContPGFTarget>),
    /// A retro payment
    Retro(PGFTarget),
}

impl ProposalType {
    /// Check if the proposal type is default
    pub fn is_default(&self) -> bool {
        matches!(self, ProposalType::Default)
    }

    /// Check if the proposal type is default
    pub fn is_default_with_wasm(&self) -> bool {
        matches!(self, ProposalType::DefaultWithWasm(_))
    }

    fn format_data(&self) -> String {
        match self {
            ProposalType::DefaultWithWasm(hash) => format!("Hash: {}", &hash),
            ProposalType::Default => "".to_string(),
            ProposalType::PGFSteward(addresses) => format!(
                "Addresses:{}",
                addresses
                    .iter()
                    .map(|add_remove| format!("\n  {}", &add_remove))
                    .join("")
            ),
            ProposalType::PGFPayment(actions) => format!(
                "Actions:{}",
                actions
                    .iter()
                    .map(|action| format!("\n  {}", &action))
                    .join("")
            ),
        }
    }
}

impl Display for ProposalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalType::Default => write!(f, "Default"),
            ProposalType::DefaultWithWasm(_) => write!(f, "Default with Wasm"),
            ProposalType::PGFSteward(_) => write!(f, "PGF steward"),
            ProposalType::PGFPayment(_) => write!(f, "PGF funding"),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ProposalTypeError {
    #[error("Invalid proposal type.")]
    InvalidProposalType,
}

impl TryFrom<StewardsUpdate> for BTreeSet<AddRemove<Address>> {
    type Error = ProposalTypeError;

    fn try_from(value: StewardsUpdate) -> Result<Self, Self::Error> {
        let mut data = BTreeSet::default();

        if value.add.is_some() {
            data.insert(AddRemove::Add(value.add.unwrap()));
        }
        for steward in value.remove {
            data.insert(AddRemove::Remove(steward));
        }
        Ok(data)
    }
}

impl TryFrom<PgfSteward> for AddRemove<Address> {
    type Error = ProposalTypeError;

    fn try_from(value: PgfSteward) -> Result<Self, Self::Error> {
        match value.action {
            PgfAction::Add => Ok(AddRemove::Add(value.address)),
            PgfAction::Remove => Ok(AddRemove::Remove(value.address)),
        }
    }
}

impl From<PgfContinuous> for PGFAction {
    fn from(value: PgfContinuous) -> Self {
        match value.action {
            PgfAction::Add => {
                PGFAction::Continuous(AddRemove::Add(value.target))
            }
            PgfAction::Remove => {
                PGFAction::Continuous(AddRemove::Remove(value.target))
            }
        }
    }
}

impl From<PgfRetro> for PGFAction {
    fn from(value: PgfRetro) -> Self {
        PGFAction::Retro(value.target)
    }
}

impl Display for PGFAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PGFAction::Continuous(add_remove) => {
                write!(f, "Continuous: {}", &add_remove)
            }
            PGFAction::Retro(target) => write!(f, "Retroactive: {}", &target),
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshDeserializer)]
/// Proposal representation when fetched from the storage
pub struct StorageProposal {
    /// The proposal id
    pub id: u64,
    /// The proposal content
    pub content: BTreeMap<String, String>,
    /// The proposal author address
    pub author: Address,
    /// The proposal type
    pub r#type: ProposalType,
    /// The epoch from which voting is allowed
    pub voting_start_epoch: Epoch,
    /// The epoch from which voting is stopped
    pub voting_end_epoch: Epoch,
    /// The epoch from which this changes are executed
    pub activation_epoch: Epoch,
}

impl StorageProposal {
    /// Check if the proposal can be voted
    pub fn can_be_voted(
        &self,
        current_epoch: Epoch,
        is_validator: bool,
    ) -> bool {
        if is_validator {
            crate::utils::is_valid_validator_voting_period(
                current_epoch,
                self.voting_start_epoch,
                self.voting_end_epoch,
            )
        } else {
            let valid_start_epoch = current_epoch >= self.voting_start_epoch;
            let valid_end_epoch = current_epoch < self.voting_end_epoch;
            valid_start_epoch && valid_end_epoch
        }
    }

    /// Return the type of tally for the proposal
    pub fn get_tally_type(&self, is_steward: bool) -> TallyType {
        TallyType::from(self.r#type.clone(), is_steward)
    }

    /// Return the status of a proposal
    pub fn get_status(&self, current_epoch: Epoch) -> ProposalStatus {
        if self.voting_start_epoch > current_epoch {
            ProposalStatus::Pending
        } else if self.voting_start_epoch <= current_epoch
            && current_epoch < self.voting_end_epoch
        {
            ProposalStatus::OnGoing
        } else {
            ProposalStatus::Ended
        }
    }

    /// Serialize a proposal to string
    pub fn to_string_with_status(&self, current_epoch: Epoch) -> String {
        format!(
            "Proposal Id: {}
Type: {}
Author: {}
Content: {:?}
Start Epoch: {}
End Epoch: {}
Activation Epoch: {}
Status: {}
Data: {}",
            self.id,
            self.r#type,
            self.author,
            self.content,
            self.voting_start_epoch,
            self.voting_end_epoch,
            self.activation_epoch,
            self.get_status(current_epoch),
            self.r#type.format_data()
        )
    }
}

impl Display for StorageProposal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Proposal Id: {}
            {:2}Type: {}
            {:2}Author: {}
            {:2}Start Epoch: {}
            {:2}End Epoch: {}
            {:2}Activation Epoch: {}
            ",
            self.id,
            "",
            self.r#type,
            "",
            self.author,
            "",
            self.voting_start_epoch,
            "",
            self.voting_end_epoch,
            "",
            self.activation_epoch
        )
    }
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers and and strategies for governance proposals
pub mod testing {
    use namada_core::address::testing::arb_non_internal_address;
    use namada_core::chain::testing::arb_epoch;
    use namada_core::hash::testing::arb_hash;
    use namada_core::ibc::core::host::types::identifiers::{ChannelId, PortId};
    use namada_core::token::testing::arb_amount;
    use proptest::prelude::*;
    use proptest::{collection, prop_compose};

    use super::*;
    use crate::storage::vote::testing::arb_proposal_vote;

    /// Generate an arbitrary add or removal of what's generated by the supplied
    /// strategy
    pub fn arb_add_remove<
        Y: Clone + std::fmt::Debug,
        X: Strategy<Value = Y>,
    >(
        strategy: X,
    ) -> impl Strategy<Value = AddRemove<<X as Strategy>::Value>> {
        strategy.prop_flat_map(|val| {
            prop_oneof![
                Just(AddRemove::Add(val.clone())),
                Just(AddRemove::Remove(val)),
            ]
        })
    }

    prop_compose! {
        /// Generate an arbitrary PGF internal target
        pub fn arb_pgf_internal_target()(
            target in arb_non_internal_address(),
            amount in arb_amount(),
        ) -> PGFInternalTarget {
            PGFInternalTarget {
                target,
                amount,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary port ID
        pub fn arb_ibc_port_id()(id in "[a-zA-Z0-9_+.\\-\\[\\]#<>]{2,128}") -> PortId {
            PortId::new(id).expect("generated invalid port ID")
        }
    }

    prop_compose! {
        /// Generate an arbitrary channel ID
        pub fn arb_ibc_channel_id()(id: u64) -> ChannelId {
            ChannelId::new(id)
        }
    }

    prop_compose! {
        /// Generate an arbitrary PGF IBC target
        pub fn arb_pgf_ibc_target()(
            target in "[a-zA-Z0-9_]*",
            amount in arb_amount(),
            port_id in arb_ibc_port_id(),
            channel_id in arb_ibc_channel_id(),
        ) -> PGFIbcTarget {
            PGFIbcTarget {
                target,
                amount,
                port_id,
                channel_id,
            }
        }
    }

    /// Generate an arbitrary PGF target
    pub fn arb_pgf_target() -> impl Strategy<Value = PGFTarget> {
        prop_oneof![
            arb_pgf_internal_target().prop_map(PGFTarget::Internal),
            arb_pgf_ibc_target().prop_map(PGFTarget::Ibc),
        ]
    }

    prop_compose! {
        /// Generate a proposal initialization
        pub fn arb_cpgf_target()(
            target in arb_pgf_target(),
            end_epoch in arb_epoch_opt(),
            proposal_id in 0..u64::MAX,
        ) -> ContPGFTarget {
            ContPGFTarget {
                target,
                end_epoch,proposal_id
            }
        }
    }

    fn arb_epoch_opt() -> impl Strategy<Value = Option<Epoch>> {
        prop_oneof![Just(None), arb_epoch().prop_map(Some),]
    }

    /// Generate an arbitrary PGF action
    pub fn arb_pgf_action() -> impl Strategy<Value = PGFAction> {
        prop_oneof![
            arb_add_remove(arb_cpgf_target()).prop_map(PGFAction::Continuous),
            arb_pgf_target().prop_map(PGFAction::Retro),
        ]
    }

    /// Generate an arbitrary proposal type
    pub fn arb_proposal_type() -> impl Strategy<Value = ProposalType> {
        prop_oneof![
            Just(ProposalType::Default),
            arb_hash().prop_map(ProposalType::DefaultWithWasm),
            collection::btree_set(
                arb_add_remove(arb_non_internal_address()),
                0..10,
            )
            .prop_map(ProposalType::PGFSteward),
            collection::btree_set(arb_pgf_action(), 0..10)
                .prop_map(ProposalType::PGFPayment),
        ]
    }

    prop_compose! {
        /// Generate a proposal initialization
        pub fn arb_init_proposal()(
            content in arb_hash(),
            author in arb_non_internal_address(),
            r#type in arb_proposal_type(),
            voting_start_epoch in arb_epoch(),
            voting_end_epoch in arb_epoch(),
            activation_epoch in arb_epoch(),
        ) -> InitProposalData {
            InitProposalData {
                content,
                author,
                r#type,
                voting_start_epoch,
                voting_end_epoch,
                activation_epoch,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary vote proposal
        pub fn arb_vote_proposal()(
            id: u64,
            vote in arb_proposal_vote(),
            voter in arb_non_internal_address(),
        ) -> VoteProposalData {
            VoteProposalData {
                id,
                vote,
                voter
            }
        }
    }
}
