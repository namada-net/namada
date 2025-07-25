//! Host environment state.

use std::cell::RefCell;

use namada_core::address::Address;
use namada_core::chain::{BlockHeader, BlockHeight, ChainId, Epoch, Epochs};
use namada_events::{EmitEvents, EventToEmit};
use namada_gas::{Gas, GasMetering, TxGasMeter, VpGasMeter};
use namada_state::write_log::{self, WriteLog};
use namada_state::{
    DB, DBIter, Error, InMemory, PrefixIter, Result, ResultExt, State,
    StateError, StateRead, StorageHasher, StorageRead, StorageWrite,
    impl_storage_read, impl_storage_write, iter_prefix_post,
};
use namada_storage as storage;
use namada_tx::data::TxSentinel;

use crate::host_env::gas_meter::GasMeter;

impl_storage_read!(TxHostEnvState<'_, D, H>);
impl_storage_read!(VpHostEnvState<'_, D, H>);
impl_storage_write!(TxHostEnvState<'_, D, H>);

/// State with mutable write log and gas metering for tx host env.
#[derive(Debug)]
pub struct TxHostEnvState<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub write_log: &'a mut WriteLog,
    /// DB handle
    pub db: &'a D,
    /// State
    pub in_mem: &'a InMemory<H>,
    /// Tx gas meter
    pub gas_meter: &'a RefCell<GasMeter<TxGasMeter>>,
    /// Errors sentinel
    pub sentinel: &'a RefCell<TxSentinel>,
}

/// Read-only state with gas metering for VP host env.
#[derive(Debug)]
pub struct VpHostEnvState<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub write_log: &'a WriteLog,
    /// DB handle
    pub db: &'a D,
    /// State
    pub in_mem: &'a InMemory<H>,
    /// VP gas meter
    pub gas_meter: &'a RefCell<GasMeter<VpGasMeter>>,
}

impl<D, H> StateRead for TxHostEnvState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        self.write_log
    }

    fn db(&self) -> &D {
        self.db
    }

    fn in_mem(&self) -> &InMemory<Self::H> {
        self.in_mem
    }

    fn charge_gas(&self, gas: Gas) -> Result<()> {
        self.gas_meter.borrow_mut().consume(gas).map_err(|err| {
            self.sentinel.borrow_mut().set_out_of_gas();
            tracing::info!(
                "Stopping transaction execution because of gas error: {}",
                err
            );
            Error::from(StateError::Gas(err))
        })
    }
}

impl<D, H> State for TxHostEnvState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn write_log_mut(&mut self) -> &mut WriteLog {
        self.write_log
    }

    fn split_borrow(
        &mut self,
    ) -> (&mut WriteLog, &InMemory<Self::H>, &Self::D) {
        (self.write_log, (self.in_mem), (self.db))
    }
}

impl<D, H> EmitEvents for TxHostEnvState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    #[inline]
    fn emit<E>(&mut self, event: E)
    where
        E: EventToEmit,
    {
        self.write_log_mut().emit_event(event);
    }

    fn emit_many<B, E>(&mut self, event_batch: B)
    where
        B: IntoIterator<Item = E>,
        E: EventToEmit,
    {
        for event in event_batch {
            self.emit(event.into());
        }
    }
}

impl<D, H> StateRead for VpHostEnvState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        self.write_log
    }

    fn db(&self) -> &D {
        self.db
    }

    fn in_mem(&self) -> &InMemory<Self::H> {
        self.in_mem
    }

    fn charge_gas(&self, gas: Gas) -> Result<()> {
        Ok(self
            .gas_meter
            .borrow_mut()
            .consume(gas)
            .map_err(StateError::Gas)?)
    }
}
