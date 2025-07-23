use std::cell::RefCell;

use namada_events::{EmitEvents, EventToEmit};
use namada_gas::{Gas, GasMetering, TxGasMeter, VpGasMeter};
use namada_tx::data::TxSentinel;

use crate::in_memory::InMemory;
use crate::write_log::WriteLog;
use crate::{
    DBIter, DBRead, Error, Result, State, StateError, StateRead, StorageHasher,
};

/// State with mutable write log and gas metering for tx host env.
#[derive(Debug)]
pub struct TxHostEnvState<'a, S, H>
where
    S: DBRead + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub write_log: &'a mut WriteLog,
    /// DB snapshot handle
    pub db: &'a S,
    /// State
    pub in_mem: &'a InMemory<H>,
    /// Tx gas meter
    pub gas_meter: &'a RefCell<TxGasMeter>,
    /// Errors sentinel
    pub sentinel: &'a RefCell<TxSentinel>,
}

/// Read-only state with gas metering for VP host env.
#[derive(Debug)]
pub struct VpHostEnvState<'a, S, H>
where
    S: DBRead + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub write_log: &'a WriteLog,
    /// DB snapshot handle
    pub db: &'a S,
    /// State
    pub in_mem: &'a InMemory<H>,
    /// VP gas meter
    pub gas_meter: &'a RefCell<VpGasMeter>,
}

impl<S, H> StateRead for TxHostEnvState<'_, S, H>
where
    S: 'static + DBRead + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type D = S;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        self.write_log
    }

    fn db(&self) -> &S {
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

impl<S, H> State for TxHostEnvState<'_, S, H>
where
    S: 'static + DBRead + for<'iter> DBIter<'iter>,
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

impl<S, H> EmitEvents for TxHostEnvState<'_, S, H>
where
    S: 'static + DBRead + for<'iter> DBIter<'iter>,
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

impl<S, H> StateRead for VpHostEnvState<'_, S, H>
where
    S: 'static + DBRead + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type D = S;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        self.write_log
    }

    fn db(&self) -> &S {
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
