//! This middleware is to handle automatically shielding the results of a
//! shielded swap.
//!
//! Since we do not know the resulting amount of assets from the swap ahead of
//! time, we cannot create a MASP note at the onset. We instead, create a note
//! for the minimum amount, which will be shielded. All assets exceeding the
//! minimum amount will be transferred to an overflow address specified by
//! the user.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};
use std::rc::Rc;

use ibc::apps::transfer::context::TokenTransferExecutionContext;
use ibc::apps::transfer::types::error::TokenTransferError;
use ibc::apps::transfer::types::packet::PacketData;
use ibc::apps::transfer::types::{Coin, PrefixedDenom};
use ibc::core::channel::types::Version;
use ibc::core::channel::types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus, StatusValue as AckStatusValue,
};
use ibc::core::channel::types::channel::{Counterparty, Order};
use ibc::core::channel::types::error::ChannelError;
use ibc::core::channel::types::packet::Packet;
use ibc::core::host::types::identifiers::{ChannelId, ConnectionId, PortId};
use ibc::core::router::module::Module;
use ibc::core::router::types::module::ModuleExtras;
use ibc::primitives::Signer;
use ibc_middleware_module::MiddlewareModule;
use ibc_middleware_module_macros::from_middleware;
use ibc_middleware_overflow_receive::OverflowRecvContext;
use ibc_middleware_packet_forward::PacketForwardMiddleware;
use namada_core::address::{Address, InternalAddress, MULTITOKEN};
use namada_core::token;
use serde_json::{Map, Value};

use crate::context::middlewares::pfm_mod::PfmTransferModule;
use crate::msg::{NamadaMemo, OsmosisSwapMemoData};
use crate::{Error, IbcCommonContext, IbcStorageContext, TokenTransferContext};

/// A middleware for handling IBC pockets received
/// after a shielded swap. The minimum amount will
/// be shielded and the rest placed in an overflow
/// account.
pub struct ShieldedRecvModule<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    ShieldedToken: namada_systems::shielded_token::Write<<C as IbcStorageContext>::Storage>
        + Debug,
{
    /// The next middleware module
    pub next: PacketForwardMiddleware<
        PfmTransferModule<C, Params, Token, ShieldedToken>,
    >,
}

impl<C, Params, Token, ShieldedToken>
    ShieldedRecvModule<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    ShieldedToken: namada_systems::shielded_token::Write<<C as IbcStorageContext>::Storage>
        + Debug,
{
    fn insert_verifier(&self, address: Address) {
        self.next
            .next()
            .transfer_module
            .ctx
            .verifiers
            .borrow_mut()
            .insert(address);
    }

    fn get_ctx(&self) -> Rc<RefCell<C>> {
        self.next.next().transfer_module.ctx.inner.clone()
    }

    fn get_verifiers(&self) -> Rc<RefCell<BTreeSet<Address>>> {
        self.next.next().transfer_module.ctx.verifiers.clone()
    }
}

impl<C, Params, Token, ShieldedToken> Debug
    for ShieldedRecvModule<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    ShieldedToken: namada_systems::shielded_token::Write<<C as IbcStorageContext>::Storage>
        + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(ShieldedRecvModule))
            .field("next", &self.next)
            .finish()
    }
}

from_middleware! {
    impl<C, Params, Token, ShieldedToken> Module
        for ShieldedRecvModule<C, Params, Token, ShieldedToken>
    where
        C: IbcCommonContext + Debug,
        Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>
            + Debug,
        Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>
            + Debug,
        ShieldedToken: namada_systems::shielded_token::Write<<C as IbcStorageContext>::Storage>
            + Debug,
}

impl<C, Params, Token, ShieldedToken> MiddlewareModule
    for ShieldedRecvModule<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    ShieldedToken: namada_systems::shielded_token::Write<<C as IbcStorageContext>::Storage>
        + Debug,
{
    type NextMiddleware = PacketForwardMiddleware<
        PfmTransferModule<C, Params, Token, ShieldedToken>,
    >;

    fn next_middleware(&self) -> &Self::NextMiddleware {
        &self.next
    }

    fn next_middleware_mut(&mut self) -> &mut Self::NextMiddleware {
        &mut self.next
    }

    fn middleware_on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        let Ok(data) = serde_json::from_slice::<PacketData>(&packet.data)
        else {
            // NB: this isn't an ICS-20 packet
            return self.next.on_recv_packet_execute(packet, relayer);
        };
        let Ok(memo) = serde_json::from_str::<NamadaMemo<OsmosisSwapMemoData>>(
            data.memo.as_ref(),
        ) else {
            // NB: this isn't a shielded recv packet
            return self.next.on_recv_packet_execute(packet, relayer);
        };

        // NB: add shielded receiver as a tx verifier, since we
        // have confirmed this packet should be handled by the
        // shielded recv middleware
        self.insert_verifier(memo.namada.osmosis_swap.overflow_receiver);

        // NB: probably not needed to add the multitoken as a verifier
        // again, but we do it anyway, for good measure
        self.insert_verifier(MULTITOKEN);

        let result: Result<Address, _> = data.receiver.as_ref().parse();
        match result {
            Err(err) => {
                let ack = AcknowledgementStatus::error(
                    AckStatusValue::new(format!(
                        "Address {:?} is not the MASP: Failed to parse MASP \
                         address: {err}",
                        data.receiver.as_ref()
                    ))
                    .expect("Ack is not empty"),
                );
                (ModuleExtras::empty(), Some(ack.into()))
            }
            Ok(Address::Internal(InternalAddress::Masp)) => {
                self.next.on_recv_packet_execute(packet, relayer)
            }
            Ok(addr) => {
                let ack = AcknowledgementStatus::error(
                    AckStatusValue::new(format!(
                        "Shielded receive error: Address {addr} is not the \
                         MASP",
                    ))
                    .expect("Ack is not empty"),
                );
                (ModuleExtras::empty(), Some(ack.into()))
            }
        }
    }
}

impl ibc_middleware_overflow_receive::PacketMetadata
    for NamadaMemo<OsmosisSwapMemoData>
{
    type AccountId = Address;
    type Amount = token::Amount;

    fn is_overflow_receive_msg(msg: &Map<String, Value>) -> bool {
        msg.get("namada").is_some_and(|maybe_namada_obj| {
            maybe_namada_obj
                .as_object()
                .is_some_and(|namada| namada.contains_key("osmosis_swap"))
        })
    }

    fn strip_middleware_msg(
        json_obj_memo: Map<String, Value>,
    ) -> Map<String, Value> {
        json_obj_memo
    }

    fn overflow_receiver(&self) -> &Address {
        &self.namada.osmosis_swap.overflow_receiver
    }

    fn target_amount(&self) -> &token::Amount {
        &self.namada.osmosis_swap.shielded_amount
    }
}

impl<C, Params, Token, ShieldedToken> OverflowRecvContext
    for ShieldedRecvModule<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    ShieldedToken: namada_systems::shielded_token::Write<<C as IbcStorageContext>::Storage>
        + Debug,
{
    type Error = Error;
    type PacketMetadata = NamadaMemo<OsmosisSwapMemoData>;

    fn mint_coins_execute(
        &mut self,
        receiver: &Address,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error> {
        let ctx = self.get_ctx();
        let verifiers = self.get_verifiers();
        let mut token_transfer_context =
            TokenTransferContext::<_, Params, Token, ShieldedToken>::new(
                ctx, verifiers,
            );
        token_transfer_context
            .mint_coins_execute(receiver, coin)
            .map_err(|e| Error::TokenTransfer(TokenTransferError::Host(e)))
    }

    fn unescrow_coins_execute(
        &mut self,
        receiver: &Address,
        port: &PortId,
        channel: &ChannelId,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error> {
        let ctx = self.get_ctx();
        let verifiers = self.get_verifiers();
        let mut token_transfer_context =
            TokenTransferContext::<_, Params, Token, ShieldedToken>::new(
                ctx, verifiers,
            );
        token_transfer_context
            .unescrow_coins_execute(receiver, port, channel, coin)
            .map_err(|e| Error::TokenTransfer(TokenTransferError::Host(e)))
    }
}
