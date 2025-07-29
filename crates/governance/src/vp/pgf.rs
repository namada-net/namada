//! Pgf VP

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::booleans::BoolResultUnitExt;
use namada_core::storage::{self, Key};
use namada_state::StorageRead;
use namada_systems::trans_token as token;
use namada_tx::BatchedTxRef;
use namada_tx::action::{Action, PgfAction};
use namada_vp_env::{Error, Result, VpEnv};
use thiserror::Error;

use crate::address::{Address, InternalAddress};
use crate::pgf::storage::keys as pgf_storage;
use crate::{is_proposal_accepted, pgf};

/// The PGF internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);

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

/// Pgf VP
pub struct PgfVp<'ctx, CTX, TokenKeys> {
    /// Generic types for DI
    pub _marker: PhantomData<(&'ctx CTX, TokenKeys)>,
}

impl<'ctx, CTX, TokenKeys> PgfVp<'ctx, CTX, TokenKeys>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
    TokenKeys: token::Keys,
{
    /// Run the validity predicate
    pub fn validate_tx(
        ctx: &'ctx CTX,
        batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        // Find the actions applied in the tx
        let actions = ctx.read_actions()?;

        // Is VP triggered by a governance proposal?
        if is_proposal_accepted(
            &ctx.pre(),
            batched_tx
                .tx
                .data(batched_tx.cmt)
                .unwrap_or_default()
                .as_ref(),
        )? {
            return Ok(());
        }

        // There must be at least one action if any of the keys belong to PGF
        if actions.is_empty()
            && keys_changed.iter().any(pgf_storage::is_pgf_key)
        {
            tracing::info!(
                "Rejecting tx without any action written to temp storage"
            );
            return Err(Error::new_const(
                "Rejecting tx without any action written to temp storage",
            ));
        }

        // Check action authorization
        for action in actions {
            match action {
                Action::Pgf(pgf_action) => match pgf_action {
                    PgfAction::UpdateStewardCommission(address) => {
                        if !verifiers.contains(&address) {
                            tracing::info!(
                                "Unauthorized \
                                 PgfAction::UpdateStewardCommission"
                            );
                            return Err(VpError::Unauthorized(
                                "UpdateStewardCommission",
                                address,
                            )
                            .into());
                        }
                    }
                    PgfAction::ResignSteward(address) => {
                        if !verifiers.contains(&address) {
                            tracing::info!(
                                "Unauthorized PgfAction::ResignSteward"
                            );
                            return Err(VpError::Unauthorized(
                                "ResignSteward",
                                address,
                            )
                            .into());
                        }
                    }
                },
                _ => {
                    // Other actions are not relevant to PoS VP
                    continue;
                }
            }
        }

        keys_changed.iter().try_for_each(|key| {
            let key_type = KeyType::from_key::<TokenKeys>(key);

            match key_type {
                KeyType::Stewards(steward_address) => {
                    let stewards_have_increased = {
                        let total_stewards_pre =
                            pgf_storage::stewards_handle().len(&ctx.pre())?;
                        let total_stewards_post =
                            pgf_storage::stewards_handle().len(&ctx.post())?;

                        total_stewards_pre < total_stewards_post
                    };

                    if stewards_have_increased {
                        return Err(Error::new_const(
                            "Stewards can only be added via governance \
                             proposals",
                        ));
                    }

                    pgf::storage::get_steward(&ctx.post(), &steward_address)?
                        .map_or_else(
                            // if a steward resigns, check their signature
                            || {
                                verifiers.contains(&steward_address).ok_or_else(
                                    || {
                                        Error::new_alloc(format!(
                                            "The VP of the steward \
                                             {steward_address} should have \
                                             been triggered to check their \
                                             signature"
                                        ))
                                    },
                                )
                            },
                            // if a steward updates the reward distribution (so
                            // total_stewards_pre == total_stewards_post) check
                            // their signature and if commissions are valid
                            |steward| {
                                if !verifiers.contains(&steward_address) {
                                    return Err(Error::new_alloc(format!(
                                        "The VP of the steward \
                                         {steward_address} should have been \
                                         triggered to check their signature"
                                    )));
                                }
                                steward
                                    .is_valid_reward_distribution()
                                    .ok_or_else(|| {
                                        Error::new_const(
                                            "Steward commissions are invalid",
                                        )
                                    })
                            },
                        )
                }
                KeyType::Fundings => Err(Error::new_alloc(format!(
                    "Cannot update PGF fundings key: {key}"
                ))),
                KeyType::PgfInflationRate | KeyType::StewardInflationRate => {
                    Self::is_valid_parameter_change(ctx, batched_tx)
                }
                KeyType::Balance(token) => {
                    Self::is_valid_balance_change(ctx, &token)
                }
                KeyType::UnknownPgf => Err(Error::new_alloc(format!(
                    "Unknown PGF state update on key: {key}"
                ))),
                KeyType::Unknown => Ok(()),
            }
        })
    }

    /// Validate a governance parameter change
    pub fn is_valid_parameter_change(
        ctx: &'ctx CTX,
        batched_tx: &BatchedTxRef<'_>,
    ) -> Result<()> {
        batched_tx.tx.data(batched_tx.cmt).map_or_else(
            || {
                Err(Error::new_const(
                    "PGF parameter changes require tx data to be present",
                ))
            },
            |data| {
                is_proposal_accepted(&ctx.pre(), data.as_ref())?.ok_or_else(
                    || {
                        Error::new_const(
                            "PGF parameter changes can only be performed by a \
                             governance proposal that has been accepted",
                        )
                    },
                )
            },
        )
    }

    /// Validate a pgf balance change
    pub fn is_valid_balance_change(
        ctx: &'ctx CTX,
        token: &Address,
    ) -> Result<()> {
        let balance_key = TokenKeys::balance_key(token, &ADDRESS);

        let pre_balance: token::Amount =
            ctx.pre().read(&balance_key)?.unwrap_or_default();
        let post_balance: token::Amount =
            ctx.post().read(&balance_key)?.unwrap_or_default();

        let is_valid_balance = post_balance >= pre_balance;

        is_valid_balance.ok_or_else(|| {
            Error::new_const("Only governance can debit from PGF account")
        })
    }
}

#[derive(Debug)]
enum KeyType {
    Stewards(Address),
    Fundings,
    PgfInflationRate,
    StewardInflationRate,
    UnknownPgf,
    Balance(Address),
    Unknown,
}

impl KeyType {
    fn from_key<TokenKeys>(key: &storage::Key) -> Self
    where
        TokenKeys: token::Keys,
    {
        if let Some(addr) = pgf_storage::is_stewards_key(key) {
            Self::Stewards(addr.clone())
        } else if pgf_storage::is_fundings_key(key) {
            KeyType::Fundings
        } else if pgf_storage::is_pgf_inflation_rate_key(key) {
            Self::PgfInflationRate
        } else if pgf_storage::is_steward_inflation_rate_key(key) {
            Self::StewardInflationRate
        } else if let Some([token, &ADDRESS]) =
            TokenKeys::is_any_token_balance_key(key)
        {
            KeyType::Balance(token.clone())
        } else if pgf_storage::is_pgf_key(key) {
            KeyType::UnknownPgf
        } else {
            KeyType::Unknown
        }
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    use namada_core::address::testing::{btc, nam};
    use namada_core::borsh::BorshSerializeExt;
    use namada_core::chain::testing::get_dummy_header;
    use namada_core::key::RefTo;
    use namada_core::key::testing::keypair_1;
    use namada_core::token;
    use namada_gas::{TxGasMeter, VpGasMeter};
    use namada_proof_of_stake::test_utils::get_dummy_genesis_validator;
    use namada_state::testing::TestFullAccessState;
    use namada_state::{BlockHeight, Epoch, State, StateRead, TxIndex};
    use namada_token::storage_key::balance_key;
    use namada_tx::data::TxType;
    use namada_tx::{Authorization, Code, Data, Section, Tx};
    use namada_vm::WasmCacheRwAccess;
    use namada_vm::wasm::run::VpEvalWasm;
    use namada_vm::wasm::{self, VpCache};
    use namada_vp::{Address, native_vp};

    use crate::vp::pgf::ADDRESS;

    type CA = WasmCacheRwAccess;
    type Eval<S> = VpEvalWasm<<S as StateRead>::D, <S as StateRead>::H, CA>;
    type Ctx<'ctx, S> = native_vp::Ctx<'ctx, S, VpCache<CA>, Eval<S>>;
    type PgfVp<'ctx, S> =
        super::PgfVp<'ctx, Ctx<'ctx, S>, namada_token::Store<()>>;

    fn init_storage() -> TestFullAccessState {
        let mut state = TestFullAccessState::default();

        namada_proof_of_stake::test_utils::test_init_genesis::<
            _,
            namada_parameters::Store<_>,
            crate::Store<_>,
            namada_token::Store<_>,
        >(
            &mut state.restrict_writes_to_write_log(),
            namada_proof_of_stake::OwnedPosParams::default(),
            vec![get_dummy_genesis_validator()].into_iter(),
            Epoch(1),
        )
        .unwrap();

        state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .expect("Setting a dummy header shouldn't fail");
        state.in_mem_mut().begin_block(BlockHeight(1)).unwrap();

        state
    }

    fn initialize_account_balance<S>(
        state: &mut S,
        address: &Address,
        amount: token::Amount,
        token: &Address,
    ) where
        S: State,
    {
        let balance_key = balance_key(token, address);
        let _ = state
            .write_log_mut()
            .write(&balance_key, amount.serialize_to_vec())
            .expect("write failed");
        state.write_log_mut().commit_batch_and_current_tx();
    }

    #[test]
    fn test_pgf_non_native_debit() {
        let mut state = init_storage();

        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
            &btc(),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(510),
            &nam(),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(510),
            &btc(),
        );
        state.commit_block().unwrap();

        let balance_key = balance_key(&btc(), &ADDRESS);
        let keys_changed = [balance_key.clone()].into();

        let _ = state
            .write_log_mut()
            .write(
                &balance_key,
                token::Amount::native_whole(1).serialize_to_vec(),
            )
            .unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache.clone(),
        );

        let res =
            PgfVp::validate_tx(&ctx, &batched_tx, &keys_changed, &verifiers);

        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("Only governance can debit from PGF account")
        );
    }

    #[test]
    fn test_pgf_non_native_credit() {
        let mut state = init_storage();

        let gas_meter =
            RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                u64::MAX,
                namada_parameters::get_gas_scale(&state).unwrap(),
            )));
        let (vp_wasm_cache, _vp_cache_dir) =
            wasm::compilation_cache::common::testing::vp_cache();

        let tx_index = TxIndex::default();

        let signer = keypair_1();
        let signer_address = Address::from(&signer.clone().ref_to());
        let verifiers = BTreeSet::from([signer_address.clone()]);

        initialize_account_balance(
            &mut state,
            &signer_address.clone(),
            token::Amount::native_whole(510),
            &btc(),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(510),
            &nam(),
        );
        initialize_account_balance(
            &mut state,
            &ADDRESS,
            token::Amount::native_whole(510),
            &btc(),
        );
        state.commit_block().unwrap();

        let balance_key = balance_key(&btc(), &ADDRESS);
        let keys_changed = [balance_key.clone()].into();

        let _ = state
            .write_log_mut()
            .write(
                &balance_key,
                token::Amount::native_whole(10000).serialize_to_vec(),
            )
            .unwrap();

        let tx_code = vec![];
        let tx_data = vec![];

        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.set_code(Code::new(tx_code, None));
        tx.set_data(Data::new(tx_data));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.header_hash()],
            [(0, keypair_1())].into_iter().collect(),
            None,
        )));

        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = Ctx::new(
            &ADDRESS,
            &state,
            batched_tx.tx,
            batched_tx.cmt,
            &tx_index,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_wasm_cache.clone(),
        );

        let res =
            PgfVp::validate_tx(&ctx, &batched_tx, &keys_changed, &verifiers);

        assert!(res.is_ok());
    }
}
