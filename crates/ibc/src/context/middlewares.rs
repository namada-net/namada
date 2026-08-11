//! Middleware entry points on Namada.

pub mod pfm_mod;
pub mod voluntary_fees;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::rc::Rc;

use ibc::core::host::types::identifiers::PortId;
use ibc::core::router::module::Module;
use ibc::core::router::types::module::ModuleId;
use ibc_middleware_overflow_receive::OverflowReceiveMiddleware;
use ibc_middleware_packet_forward::PacketForwardMiddleware;
use namada_core::address::Address;

use self::pfm_mod::PfmTransferModule;
use self::voluntary_fees::VoluntaryFeesModule;
use crate::context::transfer_mod::TransferModule;
use crate::{IbcCommonContext, IbcStorageContext};

/// The stack of middlewares of the transfer module.
pub type TransferMiddlewares<C, Params, Token, ShieldedToken> =
    OverflowReceiveMiddleware<
        VoluntaryFeesModule<C, Params, Token, ShieldedToken>,
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
    OverflowReceiveMiddleware::wrap(VoluntaryFeesModule {
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
