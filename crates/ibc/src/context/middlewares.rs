//! Middleware entry points on Namada.

pub mod pfm_mod;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::rc::Rc;

use ibc::core::host::types::identifiers::PortId;
use ibc::core::router::module::Module;
use ibc::core::router::types::module::ModuleId;
use ibc_middleware_packet_forward::PacketForwardMiddleware;
use namada_core::address::Address;

use self::pfm_mod::PfmTransferModule;
use crate::context::transfer_mod::TransferModule;
use crate::{IbcCommonContext, IbcStorageContext};

/// The stack of middlewares of the transfer module.
pub type TransferMiddlewares<C, Params> =
    PacketForwardMiddleware<PfmTransferModule<C, Params>>;

/// Create a new instance of [`TransferMiddlewares`]
pub fn create_transfer_middlewares<C, Params>(
    ctx: Rc<RefCell<C>>,
    verifiers: Rc<RefCell<BTreeSet<Address>>>,
) -> TransferMiddlewares<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
{
    PacketForwardMiddleware::wrap(PfmTransferModule {
        transfer_module: TransferModule::new(ctx, verifiers),
        _phantom: PhantomData,
    })
}

impl<C, Params> crate::ModuleWrapper for TransferMiddlewares<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
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
