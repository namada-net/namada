//! Implementation of `IbcActions` with the protocol storage

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::rc::Rc;

use borsh::BorshDeserialize;
use ibc::apps::transfer::types::PrefixedCoin;
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use ibc::apps::transfer::types::packet::PacketData;
use ibc::core::channel::types::timeout::{TimeoutHeight, TimeoutTimestamp};
use ibc::primitives::IntoTimestamp;
use masp_primitives::asset_type::AssetType;
use namada_core::address::Address;
use namada_core::borsh::{BorshSerialize, BorshSerializeExt};
use namada_core::chain::ChainId;
use namada_core::ibc::PGFIbcTarget;
use namada_core::tendermint::Time as TmTime;
use namada_core::token::Amount;
use namada_events::EmitEvents;
use namada_state::{
    BlockHeader, BlockHeight, Epoch, Epochs, Key, Result, ResultExt, State,
    StorageRead, StorageWrite, TxIndex,
};
use namada_systems::{parameters, trans_token};

use crate::event::IbcEvent;
use crate::{
    IbcActions, IbcCommonContext, IbcStorageContext, MsgTransfer,
    storage as ibc_storage,
};

/// IBC protocol context
#[derive(Debug)]
pub struct IbcProtocolContext<'a, S, Token> {
    state: &'a mut S,
    /// Marker for DI types
    _marker: PhantomData<Token>,
}

impl<S, Token> StorageRead for IbcProtocolContext<'_, S, Token>
where
    S: State,
{
    type PrefixIter<'iter>
        = <S as StorageRead>::PrefixIter<'iter>
    where
        Self: 'iter;

    fn read_bytes(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        self.state.read_bytes(key)
    }

    fn has_key(&self, key: &Key) -> Result<bool> {
        self.state.has_key(key)
    }

    fn has_conversion(&self, asset_type: &AssetType) -> Result<bool> {
        self.state.has_conversion(asset_type)
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>> {
        self.state.iter_prefix(prefix)
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>> {
        self.state.iter_next(iter)
    }

    fn get_chain_id(&self) -> Result<ChainId> {
        self.state.get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight> {
        self.state.get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>> {
        StorageRead::get_block_header(self.state, height)
    }

    fn get_block_epoch(&self) -> Result<Epoch> {
        self.state.get_block_epoch()
    }

    fn get_pred_epochs(&self) -> Result<Epochs> {
        self.state.get_pred_epochs()
    }

    fn get_tx_index(&self) -> Result<TxIndex> {
        self.state.get_tx_index()
    }

    fn get_native_token(&self) -> Result<Address> {
        self.state.get_native_token()
    }
}

impl<S, Token> StorageWrite for IbcProtocolContext<'_, S, Token>
where
    S: State,
{
    fn write_bytes(&mut self, key: &Key, val: impl AsRef<[u8]>) -> Result<()> {
        self.state.write_bytes(key, val)
    }

    fn delete(&mut self, key: &Key) -> Result<()> {
        self.state.delete(key)
    }
}

impl<S, Token> IbcStorageContext for IbcProtocolContext<'_, S, Token>
where
    S: State + EmitEvents,
    Token: trans_token::Keys
        + trans_token::Read<S>
        + trans_token::Write<S>
        + trans_token::Events<S>,
{
    type Storage = Self;

    fn storage(&self) -> &Self::Storage {
        self
    }

    fn storage_mut(&mut self) -> &mut Self::Storage {
        self
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<()> {
        // There's no gas cost for protocol, we can ignore result
        self.state.write_log_mut().emit_event(event);
        Ok(())
    }

    /// Transfer token
    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        Token::transfer(self.state, token, src, dest, amount)
    }

    /// Mint token
    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        ibc_storage::mint_tokens_and_emit_event::<_, Token>(
            self.state, target, token, amount,
        )
    }

    /// Burn token
    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        ibc_storage::burn_tokens::<_, Token>(self.state, target, token, amount)
    }

    fn insert_verifier(&mut self, _verifier: &Address) -> Result<()> {
        Ok(())
    }

    fn log_string(&self, message: String) {
        tracing::trace!(message);
    }
}

impl<S, Token> IbcCommonContext for IbcProtocolContext<'_, S, Token>
where
    S: State + EmitEvents,
    Token: trans_token::Keys
        + trans_token::Read<S>
        + trans_token::Write<S>
        + trans_token::Events<S>,
{
}

/// Transfer tokens over IBC
pub fn transfer_over_ibc<'a, S, Params, Token, Transfer>(
    state: &'a mut S,
    token: &Address,
    source: &Address,
    target: &PGFIbcTarget,
) -> Result<()>
where
    S: 'a + State + EmitEvents,
    Params: parameters::Read<
            <IbcProtocolContext<'a, S, Token> as IbcStorageContext>::Storage,
        >,
    Token: trans_token::Keys
        + trans_token::Write<S>
        + trans_token::Events<S>
        + Debug,
    Transfer: BorshSerialize + BorshDeserialize,
{
    let token = PrefixedCoin {
        denom: token.to_string().parse().expect("invalid token"),
        amount: target.amount.into(),
    };
    let packet_data = PacketData {
        token,
        sender: source.to_string().into(),
        receiver: target.target.clone().into(),
        memo: String::default().into(),
    };
    let ctx = IbcProtocolContext {
        state,
        _marker: PhantomData,
    };
    let min_duration = Params::epoch_duration_parameter(&ctx)?.min_duration;
    #[allow(clippy::arithmetic_side_effects)]
    let timeout_timestamp = ctx
        .state
        .in_mem()
        .header
        .as_ref()
        .expect("The header should exist")
        .time
        + min_duration;
    let timeout_timestamp =
        TmTime::try_from(timeout_timestamp).into_storage_result()?;
    let timeout_timestamp = TimeoutTimestamp::At(
        timeout_timestamp.into_timestamp().into_storage_result()?,
    );
    let message = IbcMsgTransfer {
        port_id_on_a: target.port_id.clone(),
        chan_id_on_a: target.channel_id.clone(),
        packet_data,
        timeout_height_on_b: TimeoutHeight::Never,
        timeout_timestamp_on_b: timeout_timestamp,
    };
    let data = MsgTransfer::<Transfer> {
        message,
        transfer: None,
    }
    .serialize_to_vec();

    // Use an empty verifiers set placeholder for validation, this is only
    // needed in txs and not protocol
    let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));
    let mut actions = IbcActions::<_, Params, Token>::new(
        Rc::new(RefCell::new(ctx)),
        verifiers,
    );
    actions.execute::<Transfer>(&data).into_storage_result()?;

    Ok(())
}
