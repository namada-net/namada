//! IBC lower-level functions for transactions.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use namada_core::address::Address;
use namada_core::masp_primitives::asset_type::AssetType;
use namada_core::token::Amount;
use namada_events::Event;
use namada_ibc::context::middlewares::create_transfer_middlewares;
pub use namada_ibc::event::{IbcEvent, IbcEventType};
pub use namada_ibc::storage::{
    burn_tokens, client_state_key, is_ibc_key, mint_limit_key, mint_tokens,
    throughput_limit_key, unlimited_channel_key, upgraded_client_state_key,
    upgraded_consensus_state_key,
};
pub use namada_ibc::trace::ibc_token;
pub use namada_ibc::{
    IbcActions, IbcCommonContext, IbcStorageContext, NftTransferModule,
    ProofSpec, TransferModule,
};
use namada_state::in_mem_virtual_storage;
use namada_tx_env::TxEnv;

use crate::{Ctx, Result, parameters, token};

/// IBC actions to handle an IBC message. The `verifiers` inserted into the set
/// must be inserted into the tx context with `Ctx::insert_verifier` after tx
/// execution.
pub fn ibc_actions(
    ctx: &mut Ctx,
) -> IbcActions<
    '_,
    Ctx,
    crate::parameters::Store<Ctx>,
    token::Store<Ctx>,
    token::ShieldedStore<Ctx>,
> {
    let ctx = Rc::new(RefCell::new(ctx.clone()));
    let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));
    let mut actions = IbcActions::new(ctx.clone(), verifiers.clone());
    let module = create_transfer_middlewares::<
        _,
        parameters::Store<Ctx>,
        token::Store<Ctx>,
        token::ShieldedStore<Ctx>,
    >(ctx.clone(), verifiers);
    actions.add_transfer_module(module);
    let module = NftTransferModule::<Ctx, token::Store<Ctx>>::new(ctx);
    actions.add_transfer_module(module);
    actions
}

impl IbcStorageContext for Ctx {
    type Storage = Self;

    fn storage(&self) -> &Self::Storage {
        self
    }

    fn storage_mut(&mut self) -> &mut Self::Storage {
        self
    }

    fn log_string(&self, message: String) {
        super::log_string(message);
    }

    fn has_conversion(&self, asset_type: &AssetType) -> Result<bool> {
        Ok(self
            .read_temp(&in_mem_virtual_storage::has_conversion_key(asset_type))?
            .unwrap_or_default())
    }

    fn emit_event(&mut self, event: Event) -> Result<()> {
        <Ctx as TxEnv>::emit_event(self, event)
    }

    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        token::transfer(self, src, dest, token, amount)
    }

    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        mint_tokens::<_, token::Store<_>>(self, target, token, amount)
    }

    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        burn_tokens::<_, token::Store<_>>(self, target, token, amount)
    }

    fn insert_verifier(&mut self, addr: &Address) -> Result<()> {
        TxEnv::insert_verifier(self, addr)
    }
}

impl IbcCommonContext for Ctx {}
