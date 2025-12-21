//! ExecutionContext implementation for IBC

use ibc::core::channel::types::channel::ChannelEnd;
use ibc::core::channel::types::commitment::{
    AcknowledgementCommitment, PacketCommitment,
};
use ibc::core::channel::types::packet::Receipt;
use ibc::core::client::context::ClientExecutionContext;
use ibc::core::client::types::Height;
use ibc::core::connection::types::ConnectionEnd;
use ibc::core::handler::types::events::IbcEvent;
use ibc::core::host::ExecutionContext;
use ibc::core::host::types::error::HostError;
use ibc::core::host::types::identifiers::{ClientId, ConnectionId, Sequence};
use ibc::core::host::types::path::{
    AckPath, ChannelEndPath, ClientConnectionPath, ClientConsensusStatePath,
    ClientStatePath, CommitmentPath, ConnectionPath, ReceiptPath, SeqAckPath,
    SeqRecvPath, SeqSendPath,
};
use ibc::primitives::Timestamp;
use namada_systems::parameters;

use super::IbcContext;
use super::client::AnyClientState;
use super::common::IbcCommonContext;
use crate::storage;

impl<C, Params> ClientExecutionContext for IbcContext<C, Params>
where
    C: IbcCommonContext,
    Params: parameters::Read<C::Storage>,
{
    type ClientStateMut = AnyClientState;

    fn store_client_state(
        &mut self,
        client_state_path: ClientStatePath,
        client_state: Self::ClientStateRef,
    ) -> Result<(), HostError> {
        self.inner
            .borrow_mut()
            .store_client_state(&client_state_path.0, client_state)
    }

    fn store_consensus_state(
        &mut self,
        consensus_state_path: ClientConsensusStatePath,
        consensus_state: Self::ConsensusStateRef,
    ) -> Result<(), HostError> {
        let client_id = &consensus_state_path.client_id;
        let height = Height::new(
            consensus_state_path.revision_number,
            consensus_state_path.revision_height,
        )
        .map_err(|_| HostError::FailedToStore {
            description: format!(
                "Invalid consensus state path: {consensus_state_path}"
            ),
        })?;
        self.inner.borrow_mut().store_consensus_state(
            client_id,
            height,
            consensus_state,
        )
    }

    fn delete_consensus_state(
        &mut self,
        consensus_state_path: ClientConsensusStatePath,
    ) -> Result<(), HostError> {
        let client_id = &consensus_state_path.client_id;
        let height = Height::new(
            consensus_state_path.revision_number,
            consensus_state_path.revision_height,
        )
        .map_err(|_| HostError::FailedToStore {
            description: format!(
                "Invalid consensus state path: {consensus_state_path}"
            ),
        })?;
        self.inner
            .borrow_mut()
            .delete_consensus_state(client_id, height)
    }

    fn store_update_meta(
        &mut self,
        client_id: ClientId,
        _height: Height,
        host_timestamp: Timestamp,
        host_height: Height,
    ) -> Result<(), HostError> {
        self.inner.borrow_mut().store_update_meta(
            &client_id,
            host_timestamp,
            host_height,
        )
    }

    fn delete_update_meta(
        &mut self,
        client_id: ClientId,
        _height: Height,
    ) -> Result<(), HostError> {
        self.inner.borrow_mut().delete_update_meta(&client_id)
    }
}

impl<C, Params> ExecutionContext for IbcContext<C, Params>
where
    C: IbcCommonContext,
    Params: parameters::Read<C::Storage>,
{
    type E = Self;

    fn get_client_execution_context(&mut self) -> &mut Self::E {
        self
    }

    fn increase_client_counter(&mut self) -> Result<(), HostError> {
        let key = storage::client_counter_key();
        self.inner.borrow_mut().increment_counter(&key)
    }

    fn store_connection(
        &mut self,
        connection_path: &ConnectionPath,
        connection_end: ConnectionEnd,
    ) -> Result<(), HostError> {
        self.inner
            .borrow_mut()
            .store_connection(&connection_path.0, connection_end)
    }

    fn store_connection_to_client(
        &mut self,
        client_connection_path: &ClientConnectionPath,
        conn_id: ConnectionId,
    ) -> Result<(), HostError> {
        self.inner
            .borrow_mut()
            .append_connection(&client_connection_path.0, conn_id)
    }

    fn increase_connection_counter(&mut self) -> Result<(), HostError> {
        let key = storage::connection_counter_key();
        self.inner.borrow_mut().increment_counter(&key)
    }

    fn store_packet_commitment(
        &mut self,
        path: &CommitmentPath,
        commitment: PacketCommitment,
    ) -> Result<(), HostError> {
        self.inner.borrow_mut().store_packet_commitment(
            &path.port_id,
            &path.channel_id,
            path.sequence,
            commitment,
        )
    }

    fn delete_packet_commitment(
        &mut self,
        path: &CommitmentPath,
    ) -> Result<(), HostError> {
        self.inner.borrow_mut().delete_packet_commitment(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn store_packet_receipt(
        &mut self,
        path: &ReceiptPath,
        _receipt: Receipt,
    ) -> Result<(), HostError> {
        self.inner.borrow_mut().store_packet_receipt(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn store_packet_acknowledgement(
        &mut self,
        path: &AckPath,
        ack_commitment: AcknowledgementCommitment,
    ) -> Result<(), HostError> {
        self.inner.borrow_mut().store_packet_ack(
            &path.port_id,
            &path.channel_id,
            path.sequence,
            ack_commitment,
        )
    }

    fn delete_packet_acknowledgement(
        &mut self,
        path: &AckPath,
    ) -> Result<(), HostError> {
        self.inner.borrow_mut().delete_packet_ack(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn store_channel(
        &mut self,
        path: &ChannelEndPath,
        channel_end: ChannelEnd,
    ) -> Result<(), HostError> {
        self.inner
            .borrow_mut()
            .store_channel(&path.0, &path.1, channel_end)
    }

    fn store_next_sequence_send(
        &mut self,
        path: &SeqSendPath,
        seq: Sequence,
    ) -> Result<(), HostError> {
        self.inner
            .borrow_mut()
            .store_next_sequence_send(&path.0, &path.1, seq)
    }

    fn store_next_sequence_recv(
        &mut self,
        path: &SeqRecvPath,
        seq: Sequence,
    ) -> Result<(), HostError> {
        self.inner
            .borrow_mut()
            .store_next_sequence_recv(&path.0, &path.1, seq)
    }

    fn store_next_sequence_ack(
        &mut self,
        path: &SeqAckPath,
        seq: Sequence,
    ) -> Result<(), HostError> {
        self.inner
            .borrow_mut()
            .store_next_sequence_ack(&path.0, &path.1, seq)
    }

    fn increase_channel_counter(&mut self) -> Result<(), HostError> {
        let key = storage::channel_counter_key();
        self.inner.borrow_mut().increment_counter(&key)
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), HostError> {
        let event: crate::event::IbcEvent =
            event.try_into().expect("The event should be converted");

        self.inner
            .borrow_mut()
            .emit_event(event.into())
            .map_err(HostError::from)
    }

    fn log_message(&mut self, message: String) -> Result<(), HostError> {
        self.inner.borrow().log_string(message);
        Ok(())
    }
}
