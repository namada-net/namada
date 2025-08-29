use namada_core::address::Address;
use namada_core::collections::{HashMap, HashSet};
use namada_core::key::common;
use namada_events::EmitEvents;
use namada_state::storage::Result;
use namada_state::{Epoch, StorageRead, StorageWrite};
use namada_trans_token as token;

use crate::types::{BondId, BondsAndUnbondsDetails, ResultSlashing, SlashType};
use crate::{BecomeValidator, GenesisValidator, OwnedPosParams, PosParams};

mod helpers;
mod state_machine;
mod state_machine_v2;
mod test_helper_fns;
mod test_pos;
mod test_slash_and_redel;
mod test_validator;
mod utils;

/// Gov impl type
pub type GovStore<S> = namada_governance::Store<S>;

/// DI indirection
pub fn init_genesis_helper<S>(
    storage: &mut S,
    params: &PosParams,
    validators: impl Iterator<Item = GenesisValidator>,
    current_epoch: namada_core::chain::Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::test_utils::init_genesis_helper::<S, GovStore<_>, token::Store<_>>(
        storage,
        params,
        validators,
        current_epoch,
    )
}

/// DI indirection
pub fn test_init_genesis<S>(
    storage: &mut S,
    owned: OwnedPosParams,
    validators: impl Iterator<Item = GenesisValidator> + Clone,
    current_epoch: namada_core::chain::Epoch,
) -> Result<PosParams>
where
    S: StorageRead + StorageWrite,
{
    crate::test_utils::test_init_genesis::<
        S,
        namada_parameters::Store<_>,
        GovStore<_>,
        token::Store<_>,
    >(storage, owned, validators, current_epoch)
}

/// DI indirection
pub fn read_pos_params<S>(storage: &S) -> Result<PosParams>
where
    S: StorageRead,
{
    crate::storage::read_pos_params::<S, GovStore<S>>(storage)
}

/// DI indirection
pub fn bond_tokens<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    amount: token::Amount,
    current_epoch: Epoch,
    offset_opt: Option<u64>,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::bond_tokens::<S, GovStore<S>, token::Store<_>>(
        storage,
        source,
        validator,
        amount,
        current_epoch,
        offset_opt,
    )
}

/// DI indirection
pub fn unbond_tokens<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    amount: token::Amount,
    current_epoch: Epoch,
    is_redelegation: bool,
) -> Result<ResultSlashing>
where
    S: StorageRead + StorageWrite,
{
    crate::unbond_tokens::<S, GovStore<S>>(
        storage,
        source,
        validator,
        amount,
        current_epoch,
        is_redelegation,
    )
}

/// DI indirection
pub fn bonds_and_unbonds<S>(
    storage: &S,
    source: Option<Address>,
    validator: Option<Address>,
) -> Result<BondsAndUnbondsDetails>
where
    S: StorageRead,
{
    crate::queries::bonds_and_unbonds::<S, GovStore<S>>(
        storage, source, validator,
    )
}

/// DI indirection
pub fn change_consensus_key<S>(
    storage: &mut S,
    validator: &Address,
    consensus_key: &common::PublicKey,
    current_epoch: Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::change_consensus_key::<S, GovStore<S>>(
        storage,
        validator,
        consensus_key,
        current_epoch,
    )
}

/// DI indirection
pub fn process_slashes<S>(
    storage: &mut S,
    events: &mut impl EmitEvents,
    current_epoch: Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::slashing::process_slashes::<S, GovStore<S>>(
        storage,
        events,
        current_epoch,
    )
}

/// DI indirection
pub fn unjail_validator<S>(
    storage: &mut S,
    validator: &Address,
    current_epoch: Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::unjail_validator::<S, GovStore<S>>(storage, validator, current_epoch)
}

/// DI indirection
pub fn become_validator<S>(
    storage: &mut S,
    args: BecomeValidator<'_>,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::become_validator::<S, GovStore<S>>(storage, args)
}

/// DI indirection
pub fn withdraw_tokens<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    current_epoch: Epoch,
) -> Result<token::Amount>
where
    S: StorageRead + StorageWrite + EmitEvents,
{
    crate::withdraw_tokens::<S, GovStore<S>, token::Store<_>>(
        storage,
        source,
        validator,
        current_epoch,
    )
}

/// DI indirection
pub fn redelegate_tokens<S>(
    storage: &mut S,
    delegator: &Address,
    src_validator: &Address,
    dest_validator: &Address,
    current_epoch: Epoch,
    amount: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::redelegate_tokens::<S, GovStore<S>>(
        storage,
        delegator,
        src_validator,
        dest_validator,
        current_epoch,
        amount,
    )
}

/// DI indirection
pub fn bond_amount<S>(
    storage: &S,
    bond_id: &BondId,
    epoch: Epoch,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    crate::bond_amount::<S, GovStore<S>>(storage, bond_id, epoch)
}

/// DI indirection
pub fn deactivate_validator<S>(
    storage: &mut S,
    validator: &Address,
    current_epoch: Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::deactivate_validator::<S, GovStore<S>>(
        storage,
        validator,
        current_epoch,
    )
}

/// DI indirection
pub fn reactivate_validator<S>(
    storage: &mut S,
    validator: &Address,
    current_epoch: Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::reactivate_validator::<S, GovStore<S>>(
        storage,
        validator,
        current_epoch,
    )
}

/// DI indirection
pub fn update_validator_deltas<S>(
    storage: &mut S,
    params: &OwnedPosParams,
    validator: &Address,
    delta: token::Change,
    current_epoch: namada_core::chain::Epoch,
    offset_opt: Option<u64>,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::update_validator_deltas::<S, GovStore<S>>(
        storage,
        params,
        validator,
        delta,
        current_epoch,
        offset_opt,
    )
}

/// DI indirection
pub fn read_below_threshold_validator_set_addresses<S>(
    storage: &S,
    epoch: namada_core::chain::Epoch,
) -> Result<HashSet<Address>>
where
    S: StorageRead,
{
    crate::storage::read_below_threshold_validator_set_addresses::<S, GovStore<S>>(
        storage, epoch,
    )
}

/// DI indirection
#[allow(clippy::too_many_arguments)]
pub fn slash<S>(
    storage: &mut S,
    params: &PosParams,
    current_epoch: Epoch,
    evidence_epoch: Epoch,
    evidence_block_height: impl Into<u64>,
    slash_type: SlashType,
    validator: &Address,
    validator_set_update_epoch: Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    crate::slashing::slash::<S, GovStore<S>>(
        storage,
        params,
        current_epoch,
        evidence_epoch,
        evidence_block_height,
        slash_type,
        validator,
        validator_set_update_epoch,
    )
}

/// DI indirection
pub fn find_delegations<S>(
    storage: &S,
    owner: &Address,
    epoch: &Epoch,
) -> Result<HashMap<Address, token::Amount>>
where
    S: StorageRead,
{
    crate::queries::find_delegations::<S, GovStore<S>>(storage, owner, epoch)
}
