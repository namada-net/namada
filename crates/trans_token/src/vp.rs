//! Native VP for multitokens

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::address::{Address, GOV, InternalAddress, POS};
use namada_core::booleans::BoolResultUnitExt;
use namada_core::collections::HashMap;
use namada_core::storage::{Key, KeySeg};
use namada_core::token::Amount;
use namada_systems::{governance, parameters};
use namada_tx::BatchedTxRef;
use namada_tx::action::{
    Action, Bond, ClaimRewards, GovAction, PosAction, Withdraw,
};
use namada_vp_env::{Error, Result, VpEnv};

use crate::StorageRead;
use crate::storage_key::{
    is_any_minted_balance_key, is_any_minter_key, is_any_token_balance_key,
    is_any_token_parameter_key, minter_key,
};

/// The owner of some balance change.
#[derive(Copy, Clone, Eq, PartialEq)]
enum Owner<'a> {
    Account(&'a Address),
    Protocol,
}

/// Multitoken VP
pub struct MultitokenVp<'ctx, CTX, Params, Gov> {
    /// Generic types for DI
    pub _marker: PhantomData<(&'ctx CTX, Params, Gov)>,
}

impl<'ctx, CTX, Params, Gov> MultitokenVp<'ctx, CTX, Params, Gov>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
    Params: parameters::Read<<CTX as VpEnv<'ctx>>::Pre>,
    Gov: governance::Read<<CTX as VpEnv<'ctx>>::Pre>,
{
    /// Run the validity predicate
    pub fn validate_tx(
        ctx: &'ctx CTX,
        tx_data: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        // Is VP triggered by a governance proposal?
        if Gov::is_proposal_accepted(
            &ctx.pre(),
            tx_data.tx.data(tx_data.cmt).unwrap_or_default().as_ref(),
        )? {
            return Ok(());
        }

        let native_token = ctx.pre().get_native_token()?;
        let is_native_token_transferable =
            Params::is_native_token_transferable(&ctx.pre())?;
        let actions = ctx.read_actions()?;
        // The native token can be transferred to and out of the `PoS` and `Gov`
        // accounts, even if `is_native_token_transferable` is false
        let is_allowed_inc = |token: &Address, bal_owner: &Address| -> bool {
            *token != native_token
                || is_native_token_transferable
                || (!actions.is_empty()
                    && actions.iter().all(|action| {
                        has_bal_inc_protocol_action(
                            action,
                            if *bal_owner == POS || *bal_owner == GOV {
                                Owner::Protocol
                            } else {
                                Owner::Account(bal_owner)
                            },
                        )
                    }))
        };
        let is_allowed_dec = |token: &Address, bal_owner: &Address| -> bool {
            *token != native_token
                || is_native_token_transferable
                || (!actions.is_empty()
                    && actions.iter().all(|action| {
                        has_bal_dec_protocol_action(
                            action,
                            if *bal_owner == POS || *bal_owner == GOV {
                                Owner::Protocol
                            } else {
                                Owner::Account(bal_owner)
                            },
                        )
                    }))
        };

        let mut inc_changes: HashMap<Address, Amount> = HashMap::new();
        let mut dec_changes: HashMap<Address, Amount> = HashMap::new();
        let mut inc_mints: HashMap<Address, Amount> = HashMap::new();
        let mut dec_mints: HashMap<Address, Amount> = HashMap::new();
        for key in keys_changed {
            if let Some([token, owner]) = is_any_token_balance_key(key) {
                if !verifiers.contains(owner) {
                    return Err(Error::new_alloc(format!(
                        "The vp of the address {} has not been triggered",
                        owner
                    )));
                }

                let pre: Amount = ctx.read_pre(key)?.unwrap_or_default();
                let post: Amount = ctx.read_post(key)?.unwrap_or_default();
                match post.checked_sub(pre) {
                    Some(diff) => {
                        if !is_allowed_inc(token, owner) {
                            tracing::debug!(
                                "Native token deposit isn't allowed"
                            );
                            return Err(Error::new_const(
                                "Native token deposit isn't allowed",
                            ));
                        }
                        let change =
                            inc_changes.entry(token.clone()).or_default();
                        *change =
                            change.checked_add(diff).ok_or_else(|| {
                                Error::new_const("Overflowed in balance check")
                            })?;
                    }
                    None => {
                        if !is_allowed_dec(token, owner) {
                            tracing::debug!(
                                "Native token withdraw isn't allowed"
                            );
                            return Err(Error::new_const(
                                "Native token deposit isn't allowed",
                            ));
                        }
                        let diff = pre
                            .checked_sub(post)
                            .expect("Underflow shouldn't happen here");
                        let change =
                            dec_changes.entry(token.clone()).or_default();
                        *change =
                            change.checked_add(diff).ok_or_else(|| {
                                Error::new_const("Overflowed in balance check")
                            })?;
                    }
                }
            } else if let Some(token) = is_any_minted_balance_key(key) {
                if *token == native_token && !is_native_token_transferable {
                    tracing::debug!(
                        "Minting/Burning native token isn't allowed"
                    );
                    return Err(Error::new_const(
                        "Minting/Burning native token isn't allowed",
                    ));
                }

                let pre: Amount = ctx.read_pre(key)?.unwrap_or_default();
                let post: Amount = ctx.read_post(key)?.unwrap_or_default();
                match post.checked_sub(pre) {
                    Some(diff) => {
                        let mint = inc_mints.entry(token.clone()).or_default();
                        *mint = mint.checked_add(diff).ok_or_else(|| {
                            Error::new_const("Overflowed in balance check")
                        })?;
                    }
                    None => {
                        let diff = pre
                            .checked_sub(post)
                            .expect("Underflow shouldn't happen here");
                        let mint = dec_mints.entry(token.clone()).or_default();
                        *mint = mint.checked_add(diff).ok_or_else(|| {
                            Error::new_const("Overflowed in balance check")
                        })?;
                    }
                }
                // Check if the minter is set
                Self::is_valid_minter(ctx, token, verifiers)?;
            } else if let Some(token) = is_any_minter_key(key) {
                Self::is_valid_minter(ctx, token, verifiers)?;
            } else if is_any_token_parameter_key(key).is_some() {
                return Self::is_valid_parameter(ctx, tx_data);
            } else if key.segments.first()
                == Some(
                    &Address::Internal(InternalAddress::Multitoken).to_db_key(),
                )
            {
                // Reject when trying to update an unexpected key under
                // `#Multitoken/...`
                return Err(Error::new_alloc(format!(
                    "Unexpected change to the multitoken account: {key}"
                )));
            }
        }

        let mut all_tokens = BTreeSet::new();
        all_tokens.extend(inc_changes.keys().cloned());
        all_tokens.extend(dec_changes.keys().cloned());
        all_tokens.extend(inc_mints.keys().cloned());
        all_tokens.extend(dec_mints.keys().cloned());

        all_tokens.iter().try_for_each(|token| {
            if token.is_internal()
                && matches!(token, Address::Internal(InternalAddress::Nut(_)))
                && !verifiers.contains(token)
            {
                // Established address tokens, IbcToken and Erc20 do not have
                // VPs themselves, their validation is handled
                // by the `Multitoken` internal address,
                // but internal token Nut addresses have to verify the transfer
                return Err(Error::new_alloc(format!(
                    "Token {token} must verify the tx"
                )));
            }

            let inc_change =
                inc_changes.get(token).cloned().unwrap_or_default();
            let dec_change =
                dec_changes.get(token).cloned().unwrap_or_default();
            let inc_mint = inc_mints.get(token).cloned().unwrap_or_default();
            let dec_mint = dec_mints.get(token).cloned().unwrap_or_default();

            let token_changes_are_balanced =
                if inc_change >= dec_change && inc_mint >= dec_mint {
                    inc_change.checked_sub(dec_change)
                        == inc_mint.checked_sub(dec_mint)
                } else if (inc_change < dec_change && inc_mint >= dec_mint)
                    || (inc_change >= dec_change && inc_mint < dec_mint)
                {
                    false
                } else {
                    dec_change.checked_sub(inc_change)
                        == dec_mint.checked_sub(inc_mint)
                };

            token_changes_are_balanced.ok_or_else(|| {
                Error::new_const(
                    "The transaction's token changes are unbalanced",
                )
            })
        })
    }

    /// Return the minter if the minter is valid and the minter VP exists
    pub fn is_valid_minter(
        ctx: &'ctx CTX,
        token: &Address,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        match token {
            Address::Internal(InternalAddress::IbcToken(_)) => {
                // Check if the minter is set
                let minter_key = minter_key(token);
                match ctx.read_post::<Address>(&minter_key)? {
                    Some(minter)
                        if minter
                            == Address::Internal(InternalAddress::Ibc) =>
                    {
                        verifiers.contains(&minter).ok_or_else(|| {
                            Error::new_const("The IBC VP was not triggered")
                        })
                    }
                    _ => Err(Error::new_const(
                        "Only the IBC account is able to mint IBC tokens",
                    )),
                }
            }
            _ => Err(Error::new_alloc(format!(
                "Attempted to mint non-IBC token {token}"
            ))),
        }
    }

    /// Return if the parameter change was done via a governance proposal
    pub fn is_valid_parameter(
        ctx: &'ctx CTX,
        batched_tx: &BatchedTxRef<'_>,
    ) -> Result<()> {
        batched_tx.tx.data(batched_tx.cmt).map_or_else(
            || {
                Err(Error::new_const(
                    "Token parameter changes require tx data to be present",
                ))
            },
            |data| {
                Gov::is_proposal_accepted(&ctx.pre(), data.as_ref())?
                    .ok_or_else(|| {
                        Error::new_const(
                            "Token parameter changes can only be performed by \
                             a governance proposal that has been accepted",
                        )
                    })
            },
        )
    }
}

fn has_bal_inc_protocol_action(action: &Action, owner: Owner<'_>) -> bool {
    match action {
        Action::Pos(
            PosAction::ClaimRewards(ClaimRewards { validator, source })
            | PosAction::Withdraw(Withdraw { validator, source }),
        ) => match owner {
            Owner::Account(owner) => {
                source.as_ref().unwrap_or(validator) == owner
            }
            // NB: pos or gov's balance can increase
            Owner::Protocol => true,
        },
        // NB: only pos or gov balances can decrease with these actions
        Action::Pos(PosAction::Bond(Bond { .. }))
        | Action::Gov(GovAction::InitProposal { .. }) => {
            owner == Owner::Protocol
        }
        // NB: every other case is invalid
        _ => false,
    }
}

fn has_bal_dec_protocol_action(action: &Action, owner: Owner<'_>) -> bool {
    match action {
        Action::Pos(PosAction::Bond(Bond {
            validator, source, ..
        })) => match owner {
            Owner::Account(owner) => {
                source.as_ref().unwrap_or(validator) == owner
            }
            // NB: pos or gov's balance can decrease
            Owner::Protocol => true,
        },
        Action::Gov(GovAction::InitProposal { author: source }) => {
            match owner {
                Owner::Account(owner) => source == owner,
                // NB: pos or gov's balance can decrease
                Owner::Protocol => true,
            }
        }
        // NB: only pos or gov balances can decrease with these actions
        Action::Pos(
            PosAction::ClaimRewards(ClaimRewards { .. })
            | PosAction::Withdraw(Withdraw { .. }),
        ) => owner == Owner::Protocol,
        // NB: every other case is invalid
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use assert_matches::assert_matches;
    use namada_core::address::testing::{
        established_address_1, established_address_2, nam,
    };
    use namada_core::borsh::BorshSerializeExt;
    use namada_core::key::testing::keypair_1;
    use namada_gas::{GasMeterKind, TxGasMeter, VpGasMeter};
    use namada_ibc::trace::ibc_token;
    use namada_parameters::storage::get_native_token_transferable_key;
    use namada_state::testing::TestState;
    use namada_state::{StateRead, StorageWrite};
    use namada_tx::action::Write;
    use namada_tx::data::TxType;
    use namada_tx::{
        Authorization, BatchedTx, Code, Data, IndexedTx, Section, Tx,
    };
    use namada_vm::WasmCacheRwAccess;
    use namada_vm::wasm::VpCache;
    use namada_vm::wasm::compilation_cache::common::testing::vp_cache;
    use namada_vm::wasm::run::VpEvalWasm;
    use namada_vp::native_vp::{self, CtxPreStorageRead};

    use super::*;
    use crate::storage_key::{balance_key, minted_balance_key};

    const ADDRESS: Address = Address::Internal(InternalAddress::Multitoken);

    type CA = WasmCacheRwAccess;
    type Eval<S> = VpEvalWasm<<S as StateRead>::D, <S as StateRead>::H, CA>;
    type Ctx<'ctx, S> = native_vp::Ctx<'ctx, S, VpCache<CA>, Eval<S>>;
    type MultitokenVp<'ctx, S> = super::MultitokenVp<
        'ctx,
        Ctx<'ctx, S>,
        namada_parameters::Store<
            CtxPreStorageRead<'ctx, 'ctx, S, VpCache<CA>, Eval<S>>,
        >,
        namada_governance::Store<
            CtxPreStorageRead<'ctx, 'ctx, S, VpCache<CA>, Eval<S>>,
        >,
    >;

    fn init_state() -> TestState {
        let mut state = TestState::default();
        namada_parameters::init_test_storage(&mut state).unwrap();
        state
    }

    fn dummy_tx(state: &TestState) -> BatchedTx {
        let tx_code = vec![];
        let tx_data = vec![];
        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            tx.sechashes(),
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));
        tx.batch_first_tx()
    }

    fn transfer(
        state: &mut TestState,
        src: &Address,
        dest: &Address,
    ) -> BTreeSet<Key> {
        let mut keys_changed = BTreeSet::new();

        let src_key = balance_key(&nam(), src);
        let amount = Amount::native_whole(100);
        state
            .db_write(&src_key, amount.serialize_to_vec())
            .expect("write failed");

        // transfer 10
        let amount = Amount::native_whole(90);
        let _ = state
            .write_log_mut()
            .write(&src_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(src_key);

        let dest_key = balance_key(&nam(), dest);
        let amount = Amount::native_whole(10);
        let _ = state
            .write_log_mut()
            .write(&dest_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(dest_key);

        keys_changed
    }

    #[test]
    fn test_valid_transfer() {
        let mut state = init_state();
        let src = established_address_1();
        let dest = established_address_2();
        let keys_changed = transfer(&mut state, &src, &dest);

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        verifiers.insert(dest);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            )
            .is_ok()
        );
    }

    #[test]
    fn test_invalid_transfer() {
        let mut state = init_state();
        let src = established_address_1();
        let dest = established_address_2();
        let keys_changed = transfer(&mut state, &src, &dest);

        // receive more than 10
        let dest_key = balance_key(&nam(), &dest);
        let amount = Amount::native_whole(100);
        let _ = state
            .write_log_mut()
            .write(&dest_key, amount.serialize_to_vec())
            .expect("write failed");

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            )
            .is_err()
        );
    }

    #[test]
    fn test_valid_mint() {
        let mut state = init_state();
        let mut keys_changed = BTreeSet::new();

        // IBC token
        let token = ibc_token("/port-42/channel-42/denom");

        // mint 100
        let target = established_address_1();
        let target_key = balance_key(&token, &target);
        let amount = Amount::native_whole(100);
        let _ = state
            .write_log_mut()
            .write(&target_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(target_key);
        let minted_key = minted_balance_key(&token);
        let amount = Amount::native_whole(100);
        let _ = state
            .write_log_mut()
            .write(&minted_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minted_key);

        // minter
        let minter = Address::Internal(InternalAddress::Ibc);
        let minter_key = minter_key(&token);
        let _ = state
            .write_log_mut()
            .write(&minter_key, minter.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minter_key);

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        // The token and minter must be part of the verifier set (checked by
        // MultitokenVp)
        verifiers.insert(token);
        verifiers.insert(target);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            )
            .is_ok()
        );
    }

    #[test]
    fn test_invalid_mint() {
        let mut state = init_state();
        let mut keys_changed = BTreeSet::new();

        // mint 100
        let target = established_address_1();
        let target_key = balance_key(&nam(), &target);
        // mint more than 100
        let amount = Amount::native_whole(1000);
        let _ = state
            .write_log_mut()
            .write(&target_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(target_key);
        let minted_key = minted_balance_key(&nam());
        let amount = Amount::native_whole(100);
        let _ = state
            .write_log_mut()
            .write(&minted_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minted_key);

        // minter
        let minter = nam();
        let minter_key = minter_key(&nam());
        let _ = state
            .write_log_mut()
            .write(&minter_key, minter.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minter_key);

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            )
            .is_err()
        );
    }

    #[test]
    fn test_no_minter() {
        let mut state = init_state();
        let mut keys_changed = BTreeSet::new();

        // IBC token
        let token = ibc_token("/port-42/channel-42/denom");

        // mint 100
        let target = established_address_1();
        let target_key = balance_key(&token, &target);
        let amount = Amount::native_whole(100);
        let _ = state
            .write_log_mut()
            .write(&target_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(target_key);
        let minted_key = minted_balance_key(&token);
        let amount = Amount::native_whole(100);
        let _ = state
            .write_log_mut()
            .write(&minted_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minted_key);

        // no minter is set

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            )
            .is_err()
        );
    }

    #[test]
    fn test_invalid_minter() {
        let mut state = init_state();
        let mut keys_changed = BTreeSet::new();

        // IBC token
        let token = ibc_token("/port-42/channel-42/denom");

        // mint 100
        let target = established_address_1();
        let target_key = balance_key(&token, &target);
        let amount = Amount::native_whole(100);
        let _ = state
            .write_log_mut()
            .write(&target_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(target_key);
        let minted_key = minted_balance_key(&token);
        let amount = Amount::native_whole(100);
        let _ = state
            .write_log_mut()
            .write(&minted_key, amount.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minted_key);

        // invalid minter
        let minter = established_address_1();
        let minter_key = minter_key(&token);
        let _ = state
            .write_log_mut()
            .write(&minter_key, minter.serialize_to_vec())
            .expect("write failed");
        keys_changed.insert(minter_key);

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            )
            .is_err()
        );
    }

    #[test]
    fn test_invalid_minter_update() {
        let mut state = init_state();
        let mut keys_changed = BTreeSet::new();

        let minter_key = minter_key(&nam());
        let minter = established_address_1();
        let _ = state
            .write_log_mut()
            .write(&minter_key, minter.serialize_to_vec())
            .expect("write failed");

        keys_changed.insert(minter_key);

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let mut verifiers = BTreeSet::new();
        // for the minter
        verifiers.insert(minter);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            )
            .is_err()
        );
    }

    #[test]
    fn test_invalid_key_update() {
        let mut state = init_state();
        let mut keys_changed = BTreeSet::new();

        let key = Key::from(
            Address::Internal(InternalAddress::Multitoken).to_db_key(),
        )
        .push(&"invalid_segment".to_string())
        .unwrap();
        let _ = state
            .write_log_mut()
            .write(&key, 0.serialize_to_vec())
            .expect("write failed");

        keys_changed.insert(key);

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let verifiers = BTreeSet::new();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            )
            .is_err()
        );
    }

    #[test]
    fn test_native_token_not_transferable() {
        let mut state = init_state();
        let src = established_address_1();
        let dest = established_address_2();
        let keys_changed = transfer(&mut state, &src, &dest);

        // disable native token transfer
        let key = get_native_token_transferable_key();
        state.write(&key, false).unwrap();

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert_matches!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            ),
            Err(_)
        );
    }

    #[test]
    fn test_native_token_transferable_to_pos() {
        let mut state = init_state();
        let src = established_address_1();
        let dest = POS;
        let keys_changed = transfer(&mut state, &src, &dest);
        state
            .push_action(Action::Pos(PosAction::Bond(Bond {
                validator: established_address_1(),
                source: None,
                amount: Amount::native_whole(90),
            })))
            .unwrap();

        // disable native token transfer
        let key = get_native_token_transferable_key();
        state.write(&key, false).unwrap();

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        verifiers.insert(dest);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert_matches!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            ),
            Ok(_)
        );
    }

    #[test]
    fn test_native_token_transferable_from_gov() {
        let mut state = init_state();
        let src = GOV;
        let dest = established_address_1();
        let keys_changed = transfer(&mut state, &src, &dest);
        state
            .push_action(Action::Gov(GovAction::InitProposal {
                author: established_address_1(),
            }))
            .unwrap();

        // disable native token transfer
        let key = get_native_token_transferable_key();
        state.write(&key, false).unwrap();

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert_matches!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            ),
            Err(_)
        );
    }

    #[test]
    fn test_native_token_transferable_to_gov() {
        let mut state = init_state();
        let src = established_address_1();
        let dest = GOV;
        let keys_changed = transfer(&mut state, &src, &dest);
        state
            .push_action(Action::Gov(GovAction::InitProposal {
                author: established_address_1(),
            }))
            .unwrap();

        // disable native token transfer
        let key = get_native_token_transferable_key();
        state.write(&key, false).unwrap();

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        verifiers.insert(dest);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert_matches!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            ),
            Ok(_)
        );
    }

    /// Check that even if native token transfers are disabled, we can
    /// still claim PoS rewards.
    #[test]
    fn test_native_token_transferable_from_pos() {
        let mut state = init_state();

        // simulate claiming PoS rewards
        let src = POS;
        let dest = established_address_1();
        let keys_changed = transfer(&mut state, &src, &dest);
        state
            .push_action(Action::Pos(PosAction::ClaimRewards(ClaimRewards {
                validator: established_address_1(),
                source: None,
            })))
            .unwrap();

        // disable native token transfer
        let key = get_native_token_transferable_key();
        state.write(&key, false).unwrap();

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();
        let mut verifiers = BTreeSet::new();
        verifiers.insert(src);
        verifiers.insert(dest);
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert_matches!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            ),
            Ok(_)
        );
    }

    // The multitoken vps ensures that all the involved parties have their vp
    // triggered
    #[test]
    fn test_verifiers() {
        let mut state = init_state();
        let src1 = established_address_1();
        let dest1 = namada_core::address::MASP;
        let src2 = namada_core::address::IBC;
        let dest2 = established_address_2();
        let mut keys_changed = transfer(&mut state, &src1, &dest1);
        keys_changed.append(&mut transfer(&mut state, &src2, &dest2));

        let indexed_tx = IndexedTx::default();
        let BatchedTx { tx, cmt } = dummy_tx(&state);
        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_vp_cache, _vp_cache_dir) = vp_cache();

        let parties = BTreeSet::from([src1, dest1, src2, dest2]);

        // One at a time remove one of the expected verifiers of this
        // transaction and check that the multitoken vp rejects the tx
        for verifier in &parties {
            let mut verifiers = parties.clone();
            verifiers.remove(verifier);

            let ctx = Ctx::new(
                &ADDRESS,
                &state,
                &tx,
                &cmt,
                &indexed_tx,
                &gas_meter,
                &keys_changed,
                &verifiers,
                vp_vp_cache.clone(),
                GasMeterKind::MutGlobal,
            );

            let err_msg = format!(
                "The vp of the address {} has not been triggered",
                verifier
            );

            match MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers,
            )
            .unwrap_err()
            {
                Error::AllocMessage(msg) if msg == err_msg => (),
                _ => panic!("Test failed with an unexpected error"),
            }
        }

        // Fnally run the validation with all the required verifiers
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            &tx,
            &cmt,
            &indexed_tx,
            &gas_meter,
            &keys_changed,
            &parties,
            vp_vp_cache,
            GasMeterKind::MutGlobal,
        );

        assert!(
            MultitokenVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &parties
            )
            .is_ok()
        );
    }
}
