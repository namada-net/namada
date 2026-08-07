//! Middleware entry points on Namada.

pub mod pfm_mod;
pub mod shielded_recv;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::rc::Rc;

use ibc::apps::transfer::context::TokenTransferExecutionContext;
use ibc::apps::transfer::handler::send_transfer_execute as send_transfer_execute_base;
use ibc::apps::transfer::types::error::TokenTransferError;
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use ibc::core::channel::context::SendPacketExecutionContext;
use ibc::core::host::types::identifiers::PortId;
use ibc::core::router::module::Module;
use ibc::core::router::types::module::ModuleId;
use ibc_middleware_overflow_receive::OverflowReceiveMiddleware;
use ibc_middleware_packet_forward::PacketForwardMiddleware;
use namada_core::address::Address;

use self::pfm_mod::PfmTransferModule;
use self::shielded_recv::ShieldedRecvModule;
use crate::context::transfer_mod::TransferModule;
use crate::{IbcCommonContext, IbcStorageContext};

/// The stack of middlewares of the transfer module.
pub type TransferMiddlewares<C, Params, Token, ShieldedToken> =
    OverflowReceiveMiddleware<
        ShieldedRecvModule<C, Params, Token, ShieldedToken>,
    >;

/// Create a new instance of [`TransferMiddlewares`]
pub fn create_transfer_middlewares<C, Params, Token, ShieldedToken>(
    ctx: Rc<RefCell<C>>,
    verifiers: Rc<RefCell<BTreeSet<Address>>>,
) -> TransferMiddlewares<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    ShieldedToken: namada_systems::shielded_token::Write<<C as IbcStorageContext>::Storage>
        + Debug,
{
    OverflowReceiveMiddleware::wrap(ShieldedRecvModule {
        next: PacketForwardMiddleware::wrap(PfmTransferModule {
            transfer_module: TransferModule::new(ctx, verifiers),
        }),
    })
}

impl<C, Params, Token, ShieldedToken> crate::ModuleWrapper
    for TransferMiddlewares<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>
        + Debug,
    ShieldedToken: namada_systems::shielded_token::Write<<C as IbcStorageContext>::Storage>
        + Debug,
{
    fn as_module(&self) -> &dyn Module {
        self
    }

    fn as_module_mut(&mut self) -> &mut dyn Module {
        self
    }

    fn module_id(&self) -> ModuleId {
        ModuleId::new(ibc::apps::transfer::types::MODULE_ID_STR.to_string())
    }

    fn port_id(&self) -> PortId {
        PortId::transfer()
    }
}

/// Executes an ICS-20 token transfer.
pub fn send_transfer_execute<SendPacketCtx, TokenCtx>(
    send_packet_ctx_a: &mut SendPacketCtx,
    token_ctx_a: &mut TokenCtx,
    msg: MsgTransfer,
) -> Result<(), TokenTransferError>
where
    SendPacketCtx: SendPacketExecutionContext,
    TokenCtx:
        TokenTransferExecutionContext + MaspUnshieldingFeesExecutionContext,
{
    macro_rules! assemble_middlewares {
        ($base:expr) => { $base };
        ($head:expr, $($tail:expr),*) => { $head(assemble_middlewares!($($tail),*)) };
    }

    // NOTE: execution order of the middlewares is from top to bottom
    let transfer = assemble_middlewares!(
        ibc_unshielding_fees_middleware,
        send_transfer_execute_base
    );

    transfer(send_packet_ctx_a, token_ctx_a, msg)
}

/// Context that handles ICS-20 MASP unshielding fees.
pub trait MaspUnshieldingFeesExecutionContext {
    /// Apply a MASP unshielding fee over the given ICS-20 packet.
    fn apply_masp_unshielding_fee(
        &self,
        msg: &mut MsgTransfer,
    ) -> Result<(), TokenTransferError>;
}

fn ibc_unshielding_fees_middleware<Next, SendPacketCtx, TokenCtx>(
    next: Next,
) -> impl FnOnce(
    &mut SendPacketCtx,
    &mut TokenCtx,
    MsgTransfer,
) -> Result<(), TokenTransferError>
where
    Next: FnOnce(
        &mut SendPacketCtx,
        &mut TokenCtx,
        MsgTransfer,
    ) -> Result<(), TokenTransferError>,
    SendPacketCtx: SendPacketExecutionContext,
    TokenCtx:
        TokenTransferExecutionContext + MaspUnshieldingFeesExecutionContext,
{
    |send_packet_ctx_a, token_ctx_a, mut msg| {
        token_ctx_a.apply_masp_unshielding_fee(&mut msg)?;

        next(send_packet_ctx_a, token_ctx_a, msg)
    }
}
