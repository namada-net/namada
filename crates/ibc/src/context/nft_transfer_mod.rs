//! IBC module for token transfer

use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;

use ibc::apps::nft_transfer::context::NftTransferValidationContext;
use ibc::apps::nft_transfer::module::{
    on_acknowledgement_packet_execute, on_acknowledgement_packet_validate,
    on_chan_close_confirm_execute, on_chan_close_confirm_validate,
    on_chan_close_init_execute, on_chan_close_init_validate,
    on_chan_open_ack_execute, on_chan_open_ack_validate,
    on_chan_open_confirm_execute, on_chan_open_confirm_validate,
    on_chan_open_init_execute, on_chan_open_try_execute,
    on_recv_packet_execute, on_timeout_packet_execute,
    on_timeout_packet_validate,
};
use ibc::apps::nft_transfer::types::MODULE_ID_STR;
use ibc::apps::nft_transfer::types::error::NftTransferError;
use ibc::core::channel::types::Version;
use ibc::core::channel::types::acknowledgement::Acknowledgement;
use ibc::core::channel::types::channel::{Counterparty, Order};
use ibc::core::channel::types::error::ChannelError;
use ibc::core::channel::types::packet::Packet;
use ibc::core::host::types::identifiers::{ChannelId, ConnectionId, PortId};
use ibc::core::router::module::Module;
use ibc::core::router::types::module::{ModuleExtras, ModuleId};
use ibc::primitives::Signer;
use namada_systems::trans_token;

use super::common::IbcCommonContext;
use super::nft_transfer::NftTransferContext;
use super::transfer_mod::ModuleWrapper;

/// IBC module for NFT transfer
#[derive(Debug)]
pub struct NftTransferModule<C, Token>
where
    C: IbcCommonContext,
{
    /// IBC actions
    pub ctx: NftTransferContext<C, Token>,
}

impl<C, Token> NftTransferModule<C, Token>
where
    C: IbcCommonContext,
    Token: trans_token::Keys,
{
    /// Make a new module
    pub fn new(ctx: Rc<RefCell<C>>) -> Self {
        Self {
            ctx: NftTransferContext::new(ctx),
        }
    }
}

impl<C, Token> ModuleWrapper for NftTransferModule<C, Token>
where
    C: IbcCommonContext + Debug,
    Token: trans_token::Keys + Debug,
{
    fn as_module(&self) -> &dyn Module {
        self
    }

    fn as_module_mut(&mut self) -> &mut dyn Module {
        self
    }

    fn module_id(&self) -> ModuleId {
        ModuleId::new(MODULE_ID_STR.to_string())
    }

    fn port_id(&self) -> PortId {
        self.ctx.get_port().expect("The port ID should be set")
    }
}

impl<C, Token> Module for NftTransferModule<C, Token>
where
    C: IbcCommonContext + Debug,
    Token: trans_token::Keys + Debug,
{
    #[allow(clippy::too_many_arguments)]
    fn on_chan_open_init_validate(
        &self,
        _order: Order,
        _connection_hops: &[ConnectionId],
        _port_id: &PortId,
        _channel_id: &ChannelId,
        _counterparty: &Counterparty,
        _version: &Version,
    ) -> Result<Version, ChannelError> {
        // Channel creation is permissioned: the handshake must be initiated
        // by an accepted governance proposal, which is validated before the
        // module callbacks are reached (see the IBC VP's governance bypass).
        // Non-governance `ChanOpenInit` is rejected here. This prevents
        // permissionless channels from being opened to forge vouchers
        // draining the pooled IBC escrow.
        Err(ChannelError::AppSpecific {
            description:
                "IBC channel creation requires a governance proposal"
                    .to_string(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn on_chan_open_init_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        on_chan_open_init_execute(
            &mut self.ctx,
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
        .map_err(into_channel_error)
    }

    #[allow(clippy::too_many_arguments)]
    fn on_chan_open_try_validate(
        &self,
        _order: Order,
        _connection_hops: &[ConnectionId],
        _port_id: &PortId,
        _channel_id: &ChannelId,
        _counterparty: &Counterparty,
        _counterparty_version: &Version,
    ) -> Result<Version, ChannelError> {
        // Counterparty-initiated channels are rejected outright. Channels may
        // only be opened with Namada as the initiator (via a governance
        // proposal executing `ChanOpenInit`), in which case Namada never
        // processes a `ChanOpenTry`. See `on_chan_open_init_validate` above.
        Err(ChannelError::AppSpecific {
            description:
                "IBC channel creation is not permitted from the counterparty \
                 side"
                    .to_string(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn on_chan_open_try_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        on_chan_open_try_execute(
            &mut self.ctx,
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
        .map_err(into_channel_error)
    }

    fn on_chan_open_ack_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<(), ChannelError> {
        on_chan_open_ack_validate(
            &self.ctx,
            port_id,
            channel_id,
            counterparty_version,
        )
        .map_err(into_channel_error)
    }

    fn on_chan_open_ack_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_open_ack_execute(
            &mut self.ctx,
            port_id,
            channel_id,
            counterparty_version,
        )
        .map_err(into_channel_error)
    }

    fn on_chan_open_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        on_chan_open_confirm_validate(&self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_open_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_open_confirm_execute(&mut self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_init_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        on_chan_close_init_validate(&self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_init_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_close_init_execute(&mut self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        on_chan_close_confirm_validate(&self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_close_confirm_execute(&mut self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        _relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        let (extras, ack) = on_recv_packet_execute(&mut self.ctx, packet);
        (extras, Some(ack))
    }

    fn on_acknowledgement_packet_validate(
        &self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> Result<(), ChannelError> {
        on_acknowledgement_packet_validate(
            &self.ctx,
            packet,
            acknowledgement,
            relayer,
        )
        .map_err(into_channel_error)
    }

    fn on_acknowledgement_packet_execute(
        &mut self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), ChannelError>) {
        let (extras, result) = on_acknowledgement_packet_execute(
            &mut self.ctx,
            packet,
            acknowledgement,
            relayer,
        );
        (extras, result.map_err(into_channel_error))
    }

    fn on_timeout_packet_validate(
        &self,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<(), ChannelError> {
        on_timeout_packet_validate(&self.ctx, packet, relayer)
            .map_err(into_channel_error)
    }

    fn on_timeout_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), ChannelError>) {
        let (extras, result) =
            on_timeout_packet_execute(&mut self.ctx, packet, relayer);
        (extras, result.map_err(into_channel_error))
    }
}

fn into_channel_error(error: NftTransferError) -> ChannelError {
    ChannelError::AppSpecific {
        description: error.to_string(),
    }
}

/// Helpers for testing
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::str::FromStr;

    use ibc::apps::nft_transfer::types::{PORT_ID_STR, ack_success_b64};
    use ibc::core::channel::types::acknowledgement::AcknowledgementStatus;

    use super::*;

    /// Dummy IBC module for token transfer
    #[derive(Debug)]
    pub struct DummyNftTransferModule {}

    impl ModuleWrapper for DummyNftTransferModule {
        fn as_module(&self) -> &dyn Module {
            self
        }

        fn as_module_mut(&mut self) -> &mut dyn Module {
            self
        }

        fn module_id(&self) -> ModuleId {
            ModuleId::new(MODULE_ID_STR.to_string())
        }

        fn port_id(&self) -> PortId {
            PortId::from_str(PORT_ID_STR).unwrap()
        }
    }

    impl Module for DummyNftTransferModule {
        #[allow(clippy::too_many_arguments)]
        fn on_chan_open_init_validate(
            &self,
            _order: Order,
            _connection_hops: &[ConnectionId],
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty: &Counterparty,
            version: &Version,
        ) -> Result<Version, ChannelError> {
            Ok(version.clone())
        }

        #[allow(clippy::too_many_arguments)]
        fn on_chan_open_init_execute(
            &mut self,
            _order: Order,
            _connection_hops: &[ConnectionId],
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty: &Counterparty,
            version: &Version,
        ) -> Result<(ModuleExtras, Version), ChannelError> {
            Ok((ModuleExtras::empty(), version.clone()))
        }

        #[allow(clippy::too_many_arguments)]
        fn on_chan_open_try_validate(
            &self,
            _order: Order,
            _connection_hops: &[ConnectionId],
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty: &Counterparty,
            counterparty_version: &Version,
        ) -> Result<Version, ChannelError> {
            Ok(counterparty_version.clone())
        }

        #[allow(clippy::too_many_arguments)]
        fn on_chan_open_try_execute(
            &mut self,
            _order: Order,
            _connection_hops: &[ConnectionId],
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty: &Counterparty,
            counterparty_version: &Version,
        ) -> Result<(ModuleExtras, Version), ChannelError> {
            Ok((ModuleExtras::empty(), counterparty_version.clone()))
        }

        fn on_chan_open_ack_validate(
            &self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty_version: &Version,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_chan_open_ack_execute(
            &mut self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty_version: &Version,
        ) -> Result<ModuleExtras, ChannelError> {
            Ok(ModuleExtras::empty())
        }

        fn on_chan_open_confirm_validate(
            &self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_chan_open_confirm_execute(
            &mut self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            Ok(ModuleExtras::empty())
        }

        fn on_chan_close_init_validate(
            &self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_chan_close_init_execute(
            &mut self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            Ok(ModuleExtras::empty())
        }

        fn on_chan_close_confirm_validate(
            &self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_chan_close_confirm_execute(
            &mut self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            Ok(ModuleExtras::empty())
        }

        fn on_recv_packet_execute(
            &mut self,
            _packet: &Packet,
            _relayer: &Signer,
        ) -> (ModuleExtras, Option<Acknowledgement>) {
            (
                ModuleExtras::empty(),
                Some(AcknowledgementStatus::success(ack_success_b64()).into()),
            )
        }

        fn on_acknowledgement_packet_validate(
            &self,
            _packet: &Packet,
            _acknowledgement: &Acknowledgement,
            _relayer: &Signer,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_acknowledgement_packet_execute(
            &mut self,
            _packet: &Packet,
            _acknowledgement: &Acknowledgement,
            _relayer: &Signer,
        ) -> (ModuleExtras, Result<(), ChannelError>) {
            (ModuleExtras::empty(), Ok(()))
        }

        fn on_timeout_packet_validate(
            &self,
            _packet: &Packet,
            _relayer: &Signer,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_timeout_packet_execute(
            &mut self,
            _packet: &Packet,
            _relayer: &Signer,
        ) -> (ModuleExtras, Result<(), ChannelError>) {
            (ModuleExtras::empty(), Ok(()))
        }
    }
}
