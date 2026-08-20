//! Proof-of-Stake native validity predicate.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use namada_controller::Dec;
use namada_core::address::Address;
use namada_core::arith::checked;
use namada_core::booleans::BoolResultUnitExt;
use namada_core::storage::Key;
use namada_systems::governance;
use namada_tx::BatchedTxRef;
use namada_tx::action::{
    Action, Bond, ClaimRewards, PosAction, Redelegation, Unbond, Withdraw,
};
use namada_vp_env::{Error, Result, VpEnv};
use thiserror::Error;

use crate::storage::{
    read_owned_pos_params, read_pos_params,
    read_validator_max_commission_rate_change, read_validator_metadata,
    validator_commission_rate_handle,
};
use crate::storage_key::is_params_key;
use crate::types::BondId;
use crate::{storage_key, token};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum VpError {
    #[error(
        "Action {0} not authorized by {1} which is not part of verifier set"
    )]
    Unauthorized(&'static str, Address),
}

impl From<VpError> for Error {
    fn from(value: VpError) -> Self {
        Error::new(value)
    }
}

/// Proof-of-Stake validity predicate
pub struct PosVp<'ctx, CTX, Gov> {
    /// Generic types for DI
    pub _marker: PhantomData<(&'ctx CTX, Gov)>,
}

impl<'ctx, CTX, Gov> PosVp<'ctx, CTX, Gov>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
    Gov: governance::Read<<CTX as VpEnv<'ctx>>::Pre>,
{
    /// Run the validity predicate
    pub fn validate_tx(
        ctx: &'ctx CTX,
        batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        tracing::debug!("\nValidating PoS Tx\n");

        // Check if this is a governance proposal first
        if batched_tx
            .tx
            .data(batched_tx.cmt)
            .map(|tx_data| Gov::is_proposal_accepted(&ctx.pre(), &tx_data))
            .transpose()?
            .unwrap_or(false)
        {
            for key in keys_changed {
                if is_params_key(key) {
                    // If governance changes PoS params, the params have to be
                    // valid
                    Self::is_valid_parameter_change(ctx)?;
                }
                // Any other change from governance is allowed without further
                // checks
            }
            return Ok(());
        }

        // Find the actions applied in the tx
        let actions = ctx.read_actions()?;

        // There must be at least one action
        if actions.is_empty()
            && keys_changed.iter().any(storage_key::is_pos_key)
        {
            tracing::info!(
                "Rejecting tx without any action written to temp storage"
            );
            return Err(Error::new_const(
                "Rejecting tx without any action written to temp storage",
            ));
        }

        let mut became_validator: BTreeSet<Address> = Default::default();
        let mut deactivated: BTreeSet<Address> = Default::default();
        let mut reactivated: BTreeSet<Address> = Default::default();
        let mut unjailed: BTreeSet<Address> = Default::default();
        let mut bonds: BTreeMap<BondId, token::Amount> = Default::default();
        let mut unbonds: BTreeMap<BondId, token::Amount> = Default::default();
        let mut withdrawals: BTreeSet<BondId> = Default::default();
        // The key is src bond ID and value is pair of (dest_validator, amount)
        let mut redelegations: BTreeMap<BondId, (Address, token::Amount)> =
            Default::default();
        // The value is an optional rewards receiver
        let mut claimed_rewards: BTreeMap<BondId, Option<Address>> =
            Default::default();
        let mut changed_commission: BTreeSet<Address> = Default::default();
        let mut changed_metadata: BTreeSet<Address> = Default::default();
        let mut changed_consensus_key: BTreeSet<Address> = Default::default();

        // Accumulate changes from the actions
        for action in actions {
            match action {
                Action::Pos(pos_action) => match pos_action {
                    PosAction::BecomeValidator(address) => {
                        if !verifiers.contains(&address) {
                            tracing::info!(
                                "Unauthorized PosAction::BecomeValidator"
                            );
                            return Err(VpError::Unauthorized(
                                "BecomeValidator",
                                address,
                            )
                            .into());
                        }
                        became_validator.insert(address);
                    }
                    PosAction::DeactivateValidator(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!(
                                "Unauthorized PosAction::DeactivateValidator"
                            );
                            return Err(VpError::Unauthorized(
                                "DeactivateValidator",
                                validator,
                            )
                            .into());
                        }
                        deactivated.insert(validator);
                    }
                    PosAction::ReactivateValidator(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!(
                                "Unauthorized PosAction::ReactivateValidator"
                            );
                            return Err(VpError::Unauthorized(
                                "ReactivateValidator",
                                validator,
                            )
                            .into());
                        }
                        reactivated.insert(validator);
                    }
                    PosAction::Unjail(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!("Unauthorized PosAction::Unjail");
                            return Err(VpError::Unauthorized(
                                "Unjail", validator,
                            )
                            .into());
                        }
                        unjailed.insert(validator);
                    }
                    PosAction::Bond(Bond {
                        validator,
                        amount,
                        source,
                    }) => {
                        let bond_id = BondId {
                            source: source.unwrap_or_else(|| validator.clone()),
                            validator,
                        };
                        if !verifiers.contains(&bond_id.source) {
                            tracing::info!("Unauthorized PosAction::Bond");
                            return Err(VpError::Unauthorized(
                                "Bond",
                                bond_id.source,
                            )
                            .into());
                        }
                        bonds.insert(bond_id, amount);
                    }
                    PosAction::Unbond(Unbond {
                        validator,
                        amount,
                        source,
                    }) => {
                        let bond_id = BondId {
                            source: source.unwrap_or_else(|| validator.clone()),
                            validator,
                        };
                        if !verifiers.contains(&bond_id.source) {
                            tracing::info!("Unauthorized PosAction::Unbond");
                            return Err(VpError::Unauthorized(
                                "Unbond",
                                bond_id.source,
                            )
                            .into());
                        }
                        unbonds.insert(bond_id, amount);
                    }
                    PosAction::Withdraw(Withdraw { validator, source }) => {
                        let bond_id = BondId {
                            source: source.unwrap_or_else(|| validator.clone()),
                            validator,
                        };
                        if !verifiers.contains(&bond_id.source) {
                            tracing::info!("Unauthorized PosAction::Withdraw");
                            return Err(VpError::Unauthorized(
                                "Withdraw",
                                bond_id.source,
                            )
                            .into());
                        }
                        withdrawals.insert(bond_id);
                    }
                    PosAction::Redelegation(Redelegation {
                        src_validator,
                        dest_validator,
                        owner,
                        amount,
                    }) => {
                        if !verifiers.contains(&owner) {
                            tracing::info!(
                                "Unauthorized PosAction::Redelegation"
                            );
                            return Err(VpError::Unauthorized(
                                "Redelegation",
                                owner,
                            )
                            .into());
                        }
                        let bond_id = BondId {
                            source: owner,
                            validator: src_validator,
                        };
                        redelegations.insert(bond_id, (dest_validator, amount));
                    }
                    PosAction::ClaimRewards(ClaimRewards {
                        validator,
                        source,
                        receiver,
                    }) => {
                        let bond_id = BondId {
                            source: source.unwrap_or_else(|| validator.clone()),
                            validator,
                        };
                        if !verifiers.contains(&bond_id.source) {
                            tracing::info!(
                                "Unauthorized PosAction::ClaimRewards"
                            );
                            return Err(VpError::Unauthorized(
                                "ClaimRewards",
                                bond_id.source,
                            )
                            .into());
                        }
                        claimed_rewards.insert(bond_id, receiver);
                    }
                    PosAction::CommissionChange(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!(
                                "Unauthorized PosAction::CommissionChange"
                            );
                            return Err(VpError::Unauthorized(
                                "CommissionChange",
                                validator,
                            )
                            .into());
                        }
                        changed_commission.insert(validator);
                    }
                    PosAction::MetadataChange(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!(
                                "Unauthorized PosAction::MetadataChange"
                            );
                            return Err(VpError::Unauthorized(
                                "MetadataChange",
                                validator,
                            )
                            .into());
                        }
                        changed_metadata.insert(validator);
                    }
                    PosAction::ConsensusKeyChange(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!(
                                "Unauthorized PosAction::ConsensusKeyChange"
                            );
                            return Err(VpError::Unauthorized(
                                "ConsensusKeyChange",
                                validator,
                            )
                            .into());
                        }
                        changed_consensus_key.insert(validator);
                    }
                },
                _ => {
                    // Other actions are not relevant to PoS VP
                    continue;
                }
            }
        }

        let params = read_pos_params::<_, Gov>(&ctx.pre())?;
        let current_epoch = ctx.get_block_epoch()?;
        let pipeline_epoch = checked!(current_epoch + params.pipeline_len)?;

        // Validate new and changed validator metadata
        for validator in became_validator.iter().chain(&changed_metadata) {
            let metadata = read_validator_metadata(&ctx.post(), validator)?;
            let Some(metadata) = metadata else {
                return Err(Error::new_alloc(format!(
                    "Missing validator {validator} metadata"
                )));
            };
            let errors = metadata.validate();
            if !errors.is_empty() {
                return Err(Error::new_alloc(format!(
                    "Metadata of the validator with address {validator} are \
                     invalid: {errors:#?}",
                )));
            }
        }

        // Validate new and changed validator commission rates
        for validator in became_validator.iter().chain(&changed_commission) {
            let commission_rate = validator_commission_rate_handle(validator)
                .get(&ctx.post(), pipeline_epoch, &params)?
                .expect("Validator must have commission rate");

            // The commission rate must be a number between 0 and 1
            if commission_rate < Dec::zero() || commission_rate > Dec::one() {
                return Err(Error::new_const(
                    "The commission rate provided must be a decimal between 0 \
                     and 1.",
                ));
            }
        }

        // Validate new validator's max commission rate change
        for validator in became_validator.iter() {
            let max_commission_rate_change =
                read_validator_max_commission_rate_change(
                    &ctx.post(),
                    validator,
                )?
                .unwrap_or_default();
            // The max commission rate change must be a number between 0 and 1
            if max_commission_rate_change < Dec::zero()
                || max_commission_rate_change > Dec::one()
            {
                return Err(Error::new_const(
                    "The per-epoch maximum commission rate change provided \
                     must be a decimal between 0 and 1.",
                ));
            }
        }

        for key in keys_changed {
            if is_params_key(key) {
                return Err(Error::new_const(
                    "PoS parameter changes can only be performed by a \
                     governance proposal that has been accepted",
                ));
            }
            // TODO: validate changes keys against the accumulated changes
        }
        Ok(())
    }

    /// Return `Ok` if the changed parameters are valid
    fn is_valid_parameter_change(ctx: &'ctx CTX) -> Result<()> {
        let validation_errors: Vec<crate::parameters::ValidationError> =
            read_owned_pos_params(&ctx.post())?.validate();
        validation_errors.is_empty().ok_or_else(|| {
            let validation_errors_str =
                itertools::join(validation_errors, ", ");
            Error::new_alloc(format!(
                "PoS parameter changes were invalid: {validation_errors_str}",
            ))
        })
    }
}
