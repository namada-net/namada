//! Gas meter used in the vm.

use namada_gas::{Gas, GasMeterKind, GasMetering, TxGasMeter, VpGasMeter};

#[cfg(feature = "wasm-runtime")]
use crate::wasm::host_env::WasmGasMeter;

/// Gas meter that stores used gas in native or wasm memory
#[derive(Debug)]
pub enum GasMeter<N> {
    /// Gas is stored in native memory
    Native(N),
    /// Gas is stored in wasm memory
    #[cfg(feature = "wasm-runtime")]
    Wasm(WasmGasMeter),
}

#[cfg(feature = "wasm-runtime")]
impl<N> From<WasmGasMeter> for GasMeter<N> {
    #[inline]
    fn from(meter: WasmGasMeter) -> Self {
        Self::Wasm(meter)
    }
}

impl From<TxGasMeter> for GasMeter<TxGasMeter> {
    #[inline]
    fn from(meter: TxGasMeter) -> Self {
        Self::Native(meter)
    }
}

impl<N> GasMeter<N> {
    /// Return the [`GasMeterKind`] of this meter.
    #[inline]
    pub fn kind(&self) -> GasMeterKind {
        match self {
            Self::Native(_) => GasMeterKind::HostFn,
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(_) => GasMeterKind::MutGlobal,
        }
    }

    /// Get the inner wasm gas meter.
    #[cfg(feature = "wasm-runtime")]
    pub fn wasm(&self) -> Option<&WasmGasMeter> {
        if let Self::Wasm(meter) = self {
            Some(meter)
        } else {
            None
        }
    }

    /// Get the inner native gas meter.
    pub fn native(&self) -> Option<&N> {
        if let Self::Native(meter) = self {
            Some(meter)
        } else {
            None
        }
    }
}

impl GasMeter<TxGasMeter> {
    /// Return a placeholder [`GasMeter`] for tx gas metering.
    ///
    /// ## Safety
    ///
    /// This should only be used as an unitialized meter. Do
    /// not perform gas metering with it.
    pub const unsafe fn tx_placeholder() -> Self {
        Self::Native(unsafe { TxGasMeter::placeholder() })
    }
}

impl GasMeter<VpGasMeter> {
    /// Return a placeholder [`GasMeter`] for vp gas metering.
    ///
    /// ## Safety
    ///
    /// This should only be used as an unitialized meter. Do
    /// not perform gas metering with it.
    pub const unsafe fn vp_placeholder() -> Self {
        Self::Native(unsafe { VpGasMeter::placeholder() })
    }
}

#[cfg(feature = "wasm-runtime")]
impl<N> GasMeter<N> {
    /// Create a new gas meter.
    pub fn new<NewNative, NewWasm>(
        kind: GasMeterKind,
        native: NewNative,
        wasm: NewWasm,
    ) -> Self
    where
        NewNative: FnOnce() -> N,
        NewWasm: FnOnce() -> WasmGasMeter,
    {
        match kind {
            GasMeterKind::HostFn => Self::Native(native()),
            GasMeterKind::MutGlobal => Self::Wasm(wasm()),
        }
    }

    /// Initialize the gas meter.
    pub fn init<InitNative, InitWasm, E>(
        &mut self,
        init_native: InitNative,
        init_wasm: InitWasm,
    ) -> Result<(), E>
    where
        N: GasMetering,
        InitNative: FnOnce(&mut N) -> Result<(), E>,
        InitWasm: FnOnce(&mut WasmGasMeter) -> Result<(), E>,
    {
        match self {
            Self::Native(meter) => init_native(meter),
            Self::Wasm(meter) => init_wasm(meter),
        }
    }

    /// Flush the consumed gas to the provided meter.
    #[inline]
    pub fn flush_to_meter(self, native_meter: &mut N) -> namada_gas::Result<()>
    where
        N: GasMetering,
    {
        match self {
            Self::Native(meter) => {
                *native_meter = meter;
                Ok(())
            }
            Self::Wasm(meter) => meter.flush_to_meter(native_meter),
        }
    }
}

impl<N: GasMetering> GasMetering for GasMeter<N> {
    fn consume(&mut self, gas: Gas) -> namada_gas::Result<()> {
        match self {
            Self::Native(meter) => meter.consume(gas),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.consume(gas),
        }
    }

    fn get_initially_available_gas(&self) -> Gas {
        match self {
            Self::Native(meter) => meter.get_initially_available_gas(),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.get_initially_available_gas(),
        }
    }

    fn get_consumed_gas(&self) -> Gas {
        match self {
            Self::Native(meter) => meter.get_consumed_gas(),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.get_consumed_gas(),
        }
    }

    fn get_gas_limit(&self) -> Gas {
        match self {
            Self::Native(meter) => meter.get_gas_limit(),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.get_gas_limit(),
        }
    }

    fn get_gas_scale(&self) -> u64 {
        match self {
            Self::Native(meter) => meter.get_gas_scale(),
            #[cfg(feature = "wasm-runtime")]
            Self::Wasm(meter) => meter.get_gas_scale(),
        }
    }
}
