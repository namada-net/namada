//! Gas accounting module to track the gas usage in a block for transactions and
//! validity predicates triggered by transactions.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects
)]

pub mod event;
pub mod storage;

use std::fmt::Display;
use std::num::ParseIntError;
use std::str::FromStr;

use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::hints;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Choose the gas mmeter used for WASM instructions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GasMeterKind {
    /// Gas accounting using a host env function. Suitable for unstructed code.
    HostFn,
    /// Global mutable variable accounted inside WASM. This should only be used
    /// for trusted WASM code as a malicious code might modify the gas meter
    MutGlobal,
}

#[allow(missing_docs)]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("Transaction gas exceeded the limit of {0} gas units")]
    TransactionGasExceededError(WholeGas),
    #[error("Block gas limit exceeded")]
    BlockGasExceeded,
    #[error("Overflow during gas operations")]
    GasOverflow,
}

#[allow(missing_docs)]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GasParseError {
    #[error("Failed to parse gas: {0}")]
    Parse(ParseIntError),
    #[error("Gas overflowed")]
    Overflow,
}

// RAW GAS COSTS
// =============================================================================
// The raw gas costs exctracted from the benchmarks.
//
const COMPILE_GAS_PER_BYTE_RAW: u64 = 1_664;
const WASM_CODE_VALIDATION_GAS_PER_BYTE_RAW: u64 = 59;
const WRAPPER_TX_VALIDATION_GAS_RAW: u64 = 1_526_700;
// There's no benchmark to calculate the cost of storage occupation, so we
// define it as the cost of storage latency (which is needed for any storage
// operation and it's based on actual execution time), plus the same cost
// multiplied by an arbitrary factor that represents the higher cost of storage
// space as a resource. This way, the storage occupation cost is not completely
// free-floating but it's tied to the other costs
const STORAGE_OCCUPATION_GAS_PER_BYTE_RAW: u64 =
    PHYSICAL_STORAGE_LATENCY_PER_BYTE_RAW * (1 + 1_000);
// NOTE: this accounts for the latency of a physical drive access. For read
// accesses we have no way to tell if data was in cache or in storage. Moreover,
// the latency shouldn't really be accounted per single byte but rather per
// storage blob but this would make it more tedious to compute gas in the
// codebase. For these two reasons we just set an arbitrary value (based on
// actual SSDs latency) per byte here
const PHYSICAL_STORAGE_LATENCY_PER_BYTE_RAW: u64 = 20;
// This is based on the global average bandwidth
const NETWORK_TRANSMISSION_GAS_PER_BYTE_RAW: u64 = 848;

// The cost of accessing data from memory (both read and write mode), per byte
const MEMORY_ACCESS_GAS_PER_BYTE_RAW: u64 = 39;
// The cost of accessing data from storage, per byte
const STORAGE_ACCESS_GAS_PER_BYTE_RAW: u64 =
    93 + PHYSICAL_STORAGE_LATENCY_PER_BYTE_RAW;
// The cost of writing data to storage, per byte
const STORAGE_WRITE_GAS_PER_BYTE_RAW: u64 = MEMORY_ACCESS_GAS_PER_BYTE_RAW
    + 17_583
    + STORAGE_OCCUPATION_GAS_PER_BYTE_RAW;
// The cost of removing data from storage, per byte
const STORAGE_DELETE_GAS_PER_BYTE_RAW: u64 = MEMORY_ACCESS_GAS_PER_BYTE_RAW
    + 17_583
    + PHYSICAL_STORAGE_LATENCY_PER_BYTE_RAW;
// The cost of verifying a single signature of a transaction
const VERIFY_TX_SIG_GAS_RAW: u64 = 435_190;
// The cost for requesting one more page in wasm (64KiB)
const WASM_MEMORY_PAGE_GAS_RAW: u64 =
    MEMORY_ACCESS_GAS_PER_BYTE_RAW * 64 * 1_024;
// The cost to validate an Ibc action
const IBC_ACTION_VALIDATE_GAS_RAW: u64 = 290_935;
// The cost to execute an Ibc action
const IBC_ACTION_EXECUTE_GAS_RAW: u64 = 1_685_733;
// The cost of masp sig verification
const MASP_VERIFY_SIG_GAS_RAW: u64 = 1_908_750;
// The fixed cost of spend note verification
const MASP_FIXED_SPEND_GAS_RAW: u64 = 59_521_000;
// The variable cost of spend note verification
const MASP_VARIABLE_SPEND_GAS_RAW: u64 = 9_849_000;
// The fixed cost of convert note verification
const MASP_FIXED_CONVERT_GAS_RAW: u64 = 46_197_000;
// The variable cost of convert note verification
const MASP_VARIABLE_CONVERT_GAS_RAW: u64 = 10_245_000;
// The fixed cost of output note verification
const MASP_FIXED_OUTPUT_GAS_RAW: u64 = 53_439_000;
// The variable cost of output note verification
const MASP_VARIABLE_OUTPUT_GAS_RAW: u64 = 9_710_000;
// The cost to process a masp spend note in the bundle
const MASP_SPEND_CHECK_GAS_RAW: u64 = 405_070;
// The cost to process a masp convert note in the bundle
const MASP_CONVERT_CHECK_GAS_RAW: u64 = 188_590;
// The cost to process a masp output note in the bundle
const MASP_OUTPUT_CHECK_GAS_RAW: u64 = 204_430;
// The cost to run the final masp check in the bundle
const MASP_FINAL_CHECK_GAS_RAW: u64 = 43;
// =============================================================================

// A correction factor for non-WASM-opcodes costs. We can see that the
// gas cost we get for wasm codes (txs and vps) is much greater than what we
// would expect from the benchmarks. This is likely due to some imperfections in
// the injection tool but, most importantly, to the fact that the code we end up
// executing is an optimized version of the one we instrument. Therefore we
// provide this factor to correct the costs of non-WASM gas based on the avarage
// speedup we can observe. NOTE: we should really reduce the gas costs of WASM
// opcodes instead of increasing the gas costs of non-WASM gas, but the former
// would involve some complicated adjustments for host function calls so we
// prefer to go with the latter.
const GAS_COST_CORRECTION: u64 = 5;

// ADJUSTED GAS COSTS
// =============================================================================
// The gas costs adjusted for the correction factor.
//

// The compilation cost is reduced by a factor to compensate for the (most
// likely) presence of the cache
const COMPILE_GAS_PER_BYTE: u64 =
    COMPILE_GAS_PER_BYTE_RAW * GAS_COST_CORRECTION / 100;
const WASM_CODE_VALIDATION_GAS_PER_BYTE: u64 =
    WASM_CODE_VALIDATION_GAS_PER_BYTE_RAW * GAS_COST_CORRECTION;
const WRAPPER_TX_VALIDATION_GAS: u64 =
    WRAPPER_TX_VALIDATION_GAS_RAW * GAS_COST_CORRECTION;
const STORAGE_OCCUPATION_GAS_PER_BYTE: u64 =
    STORAGE_OCCUPATION_GAS_PER_BYTE_RAW * GAS_COST_CORRECTION;
const NETWORK_TRANSMISSION_GAS_PER_BYTE: u64 =
    NETWORK_TRANSMISSION_GAS_PER_BYTE_RAW * GAS_COST_CORRECTION;
/// The cost of accessing data from memory (both read and write mode), per byte
pub const MEMORY_ACCESS_GAS_PER_BYTE: u64 =
    MEMORY_ACCESS_GAS_PER_BYTE_RAW * GAS_COST_CORRECTION;
/// The cost of accessing data from storage, per byte
pub const STORAGE_ACCESS_GAS_PER_BYTE: u64 =
    STORAGE_ACCESS_GAS_PER_BYTE_RAW * GAS_COST_CORRECTION;
/// The cost of writing data to storage, per byte
pub const STORAGE_WRITE_GAS_PER_BYTE: u64 =
    STORAGE_WRITE_GAS_PER_BYTE_RAW * GAS_COST_CORRECTION;
/// The cost of removing data from storage, per byte
pub const STORAGE_DELETE_GAS_PER_BYTE: u64 =
    STORAGE_DELETE_GAS_PER_BYTE_RAW * GAS_COST_CORRECTION;
/// The cost of verifying a single signature of a transaction
pub const VERIFY_TX_SIG_GAS: u64 = VERIFY_TX_SIG_GAS_RAW * GAS_COST_CORRECTION;
/// The cost for requesting one more page in wasm (64KiB)
#[allow(clippy::cast_possible_truncation)] // const in u32 range
pub const WASM_MEMORY_PAGE_GAS: u32 =
    (WASM_MEMORY_PAGE_GAS_RAW * GAS_COST_CORRECTION) as u32;
/// The cost to validate an Ibc action
pub const IBC_ACTION_VALIDATE_GAS: u64 =
    IBC_ACTION_VALIDATE_GAS_RAW * GAS_COST_CORRECTION;
/// The cost to execute an Ibc action
pub const IBC_ACTION_EXECUTE_GAS: u64 =
    IBC_ACTION_EXECUTE_GAS_RAW * GAS_COST_CORRECTION;
/// The cost of masp sig verification
pub const MASP_VERIFY_SIG_GAS: u64 =
    MASP_VERIFY_SIG_GAS_RAW * GAS_COST_CORRECTION;
/// The fixed cost of spend note verification
pub const MASP_FIXED_SPEND_GAS: u64 =
    MASP_FIXED_SPEND_GAS_RAW * GAS_COST_CORRECTION;
/// The variable cost of spend note verification
pub const MASP_VARIABLE_SPEND_GAS: u64 =
    MASP_VARIABLE_SPEND_GAS_RAW * GAS_COST_CORRECTION;
/// The fixed cost of convert note verification
pub const MASP_FIXED_CONVERT_GAS: u64 =
    MASP_FIXED_CONVERT_GAS_RAW * GAS_COST_CORRECTION;
/// The variable cost of convert note verification
pub const MASP_VARIABLE_CONVERT_GAS: u64 =
    MASP_VARIABLE_CONVERT_GAS_RAW * GAS_COST_CORRECTION;
/// The fixed cost of output note verification
pub const MASP_FIXED_OUTPUT_GAS: u64 =
    MASP_FIXED_OUTPUT_GAS_RAW * GAS_COST_CORRECTION;
/// The variable cost of output note verification
pub const MASP_VARIABLE_OUTPUT_GAS: u64 =
    MASP_VARIABLE_OUTPUT_GAS_RAW * GAS_COST_CORRECTION;
/// The cost to process a masp spend note in the bundle
pub const MASP_SPEND_CHECK_GAS: u64 =
    MASP_SPEND_CHECK_GAS_RAW * GAS_COST_CORRECTION;
/// The cost to process a masp convert note in the bundle
pub const MASP_CONVERT_CHECK_GAS: u64 =
    MASP_CONVERT_CHECK_GAS_RAW * GAS_COST_CORRECTION;
/// The cost to process a masp output note in the bundle
pub const MASP_OUTPUT_CHECK_GAS: u64 =
    MASP_OUTPUT_CHECK_GAS_RAW * GAS_COST_CORRECTION;
/// The cost to run the final masp check in the bundle
pub const MASP_FINAL_CHECK_GAS: u64 =
    MASP_FINAL_CHECK_GAS_RAW * GAS_COST_CORRECTION;
// =============================================================================

/// Gas module result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// Representation of tracking gas in sub-units.
///
/// This effectively decouples gas metering from fee payment, allowing higher
/// resolution when accounting for gas while, at the same time, providing a
/// contained gas value when paying fees.
// This type should not implement the Copy trait to prevent charging gas more
// than once
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    PartialOrd,
    BorshDeserialize,
    BorshDeserializer,
    BorshSerialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
#[must_use = "Gas must be accounted for by the gas meter"]
pub struct Gas {
    pub sub: u64,
}

impl Gas {
    /// Initialize a new gas value from its sub units.
    pub const fn new(sub_units: u64) -> Self {
        Self { sub: sub_units }
    }

    /// Checked add of `Gas`. Returns `None` on overflow
    pub fn checked_add(&self, rhs: Self) -> Option<Self> {
        self.sub.checked_add(rhs.sub).map(|sub| Self { sub })
    }

    /// Checked sub of `Gas`. Returns `None` on underflow
    pub fn checked_sub(&self, rhs: Self) -> Option<Self> {
        self.sub.checked_sub(rhs.sub).map(|sub| Self { sub })
    }

    /// Checked div of `Gas`. Returns `None` if `rhs` is zero.
    pub fn checked_div(&self, rhs: u64) -> Option<Self> {
        self.sub.checked_div(rhs).map(|sub| Self { sub })
    }

    /// Converts the sub gas units to whole ones. If the sub units are not a
    /// multiple of the scale than ceil the quotient
    pub fn get_whole_gas_units(&self, scale: u64) -> WholeGas {
        let quotient = self
            .sub
            .checked_div(scale)
            .expect("Gas quotient should not overflow on checked division");
        if self
            .sub
            .checked_rem(scale)
            .expect("Gas quotient remainder should not overflow")
            == 0
        {
            quotient.into()
        } else {
            quotient
                .checked_add(1)
                .expect("Cannot overflow as the quotient is scaled down u64")
                .into()
        }
    }

    /// Generates a `Gas` instance from a `WholeGas` amount
    pub fn from_whole_units(whole: WholeGas, scale: u64) -> Option<Self> {
        scale.checked_mul(whole.into()).map(|sub| Self { sub })
    }
}

impl From<u64> for Gas {
    fn from(sub: u64) -> Self {
        Self { sub }
    }
}

impl From<Gas> for u64 {
    fn from(gas: Gas) -> Self {
        gas.sub
    }
}

/// Gas represented in whole units. Used for fee payment and to display
/// information to the user.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    Eq,
)]
pub struct WholeGas(u64);

impl From<u64> for WholeGas {
    fn from(amount: u64) -> WholeGas {
        Self(amount)
    }
}

impl From<WholeGas> for u64 {
    fn from(whole: WholeGas) -> u64 {
        whole.0
    }
}

impl FromStr for WholeGas {
    type Err = GasParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.parse().map_err(GasParseError::Parse)?))
    }
}

impl Display for WholeGas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Trait to share gas operations for transactions and validity predicates
pub trait GasMetering {
    /// Add gas cost. It will return error when the
    /// consumed gas exceeds the provided transaction gas limit, but the state
    /// will still be updated
    fn consume(&mut self, gas: Gas) -> Result<()>;

    /// Get the gas initially available to the gas meter
    ///
    /// This value will be equal to the gas limit minus some
    /// gas that may have been consumed before the current
    /// meter was initialized
    fn get_initially_available_gas(&self) -> Gas;

    /// Get the gas consumed thus far
    fn get_consumed_gas(&self) -> Gas;

    /// Get the gas limit
    fn get_gas_limit(&self) -> Gas;

    /// Get the protocol gas scale
    fn get_gas_scale(&self) -> u64;

    /// Get the amount of gas still available to the transaction
    fn get_available_gas(&self) -> Gas {
        self.get_gas_limit()
            .checked_sub(self.get_consumed_gas())
            .unwrap_or_default()
    }

    /// Add the compiling cost proportionate to the code length
    fn add_compiling_gas(&mut self, bytes_len: u64) -> Result<()> {
        self.consume(
            bytes_len
                .checked_mul(COMPILE_GAS_PER_BYTE)
                .ok_or(Error::GasOverflow)?
                .into(),
        )
    }

    /// Add the gas for loading the wasm code from storage
    fn add_wasm_load_from_storage_gas(&mut self, bytes_len: u64) -> Result<()> {
        self.consume(
            bytes_len
                .checked_mul(STORAGE_ACCESS_GAS_PER_BYTE)
                .ok_or(Error::GasOverflow)?
                .into(),
        )
    }

    /// Add the gas for validating untrusted wasm code
    fn add_wasm_validation_gas(&mut self, bytes_len: u64) -> Result<()> {
        self.consume(
            bytes_len
                .checked_mul(WASM_CODE_VALIDATION_GAS_PER_BYTE)
                .ok_or(Error::GasOverflow)?
                .into(),
        )
    }

    /// Check if the meter ran out of gas. Starts with the initial gas.
    fn check_limit(&self, gas: Gas) -> Result<()> {
        self.get_initially_available_gas()
            .checked_sub(gas)
            .ok_or_else(|| {
                Error::TransactionGasExceededError(
                    self.get_gas_limit()
                        .get_whole_gas_units(self.get_gas_scale()),
                )
            })
            .and(Ok(()))
    }
}

/// Gas metering in a transaction
#[derive(Debug)]
pub struct TxGasMeter {
    /// Track gas overflow
    gas_overflow: bool,
    /// The protocol gas scale
    gas_scale: u64,
    /// The gas limit for a transaction
    tx_gas_limit: Gas,
    /// Gas consumption of the tx
    transaction_gas: Gas,
}

/// Gas metering in a validity predicate
#[derive(Debug)]
pub struct VpGasMeter {
    /// Track gas overflow
    gas_overflow: bool,
    /// The protocol gas scale
    gas_scale: u64,
    /// The transaction gas limit
    tx_gas_limit: Gas,
    /// The gas consumed by the transaction before the Vp
    prev_meter_consumed_gas: Gas,
    /// The current gas usage in the VP
    current_gas: Gas,
}

impl GasMetering for TxGasMeter {
    fn consume(&mut self, gas: Gas) -> Result<()> {
        if self.gas_overflow {
            hints::cold();
            return Err(Error::GasOverflow);
        }

        self.transaction_gas =
            self.transaction_gas.checked_add(gas).ok_or_else(|| {
                hints::cold();
                self.gas_overflow = true;
                Error::GasOverflow
            })?;

        if self.transaction_gas > self.tx_gas_limit {
            return Err(Error::TransactionGasExceededError(
                self.tx_gas_limit.get_whole_gas_units(self.gas_scale),
            ));
        }

        Ok(())
    }

    #[inline]
    fn get_initially_available_gas(&self) -> Gas {
        self.get_gas_limit()
    }

    fn get_consumed_gas(&self) -> Gas {
        if !self.gas_overflow {
            self.transaction_gas.clone()
        } else {
            hints::cold();
            u64::MAX.into()
        }
    }

    fn get_gas_limit(&self) -> Gas {
        self.tx_gas_limit.clone()
    }

    fn get_gas_scale(&self) -> u64 {
        self.gas_scale
    }
}

impl TxGasMeter {
    /// Return a placeholder [`TxGasMeter`].
    ///
    /// ## Safety
    ///
    /// This should only be used as an unitialized meter. Do
    /// not perform gas metering with it.
    pub const unsafe fn placeholder() -> Self {
        Self {
            gas_overflow: false,
            gas_scale: 0u64,
            tx_gas_limit: Gas::new(0u64),
            transaction_gas: Gas::new(0u64),
        }
    }

    /// Initialize a new Tx gas meter. Requires a gas limit for the specific
    /// wrapper transaction and the protocol's gas scale
    pub fn new(tx_gas_limit: impl Into<Gas>, gas_scale: u64) -> Self {
        Self {
            gas_overflow: false,
            gas_scale,
            tx_gas_limit: tx_gas_limit.into(),
            transaction_gas: Gas::default(),
        }
    }

    /// Add the gas required by a wrapper transaction which is comprised of:
    ///  - cost of validating the wrapper tx
    ///  - space that the transaction requires in the block
    ///  - cost of downloading (as part of the block) the transaction bytes over
    ///    the network
    pub fn add_wrapper_gas(&mut self, tx_bytes: &[u8]) -> Result<()> {
        self.consume(WRAPPER_TX_VALIDATION_GAS.into())?;

        let bytes_len = tx_bytes.len() as u64;
        self.consume(
            bytes_len
                .checked_mul(
                    STORAGE_OCCUPATION_GAS_PER_BYTE
                        + NETWORK_TRANSMISSION_GAS_PER_BYTE,
                )
                .ok_or(Error::GasOverflow)?
                .into(),
        )
    }
}

impl GasMetering for VpGasMeter {
    fn consume(&mut self, gas: Gas) -> Result<()> {
        if self.gas_overflow {
            hints::cold();
            return Err(Error::GasOverflow);
        }

        self.current_gas =
            self.current_gas.checked_add(gas).ok_or_else(|| {
                hints::cold();
                self.gas_overflow = true;
                Error::GasOverflow
            })?;

        let current_total = self
            .prev_meter_consumed_gas
            .checked_add(self.current_gas.clone())
            .ok_or(Error::GasOverflow)?;

        if current_total > self.tx_gas_limit {
            return Err(Error::TransactionGasExceededError(
                self.tx_gas_limit.get_whole_gas_units(self.gas_scale),
            ));
        }

        Ok(())
    }

    fn get_initially_available_gas(&self) -> Gas {
        self.tx_gas_limit
            .checked_sub(self.prev_meter_consumed_gas.clone())
            .unwrap_or_default()
    }

    fn get_consumed_gas(&self) -> Gas {
        self.prev_meter_consumed_gas
            .checked_add(self.get_vp_consumed_gas())
            .unwrap_or_else(|| u64::MAX.into())
    }

    fn get_gas_limit(&self) -> Gas {
        self.tx_gas_limit.clone()
    }

    fn get_gas_scale(&self) -> u64 {
        self.gas_scale
    }
}

impl VpGasMeter {
    /// Return a placeholder [`VpGasMeter`].
    ///
    /// ## Safety
    ///
    /// This should only be used as an unitialized meter. Do
    /// not perform gas metering with it.
    pub const unsafe fn placeholder() -> Self {
        Self {
            gas_overflow: false,
            gas_scale: 0u64,
            tx_gas_limit: Gas::new(0u64),
            prev_meter_consumed_gas: Gas::new(0u64),
            current_gas: Gas::new(0u64),
        }
    }

    /// Initialize a new VP gas meter from the [`TxGasMeter`]
    pub fn new_from_tx_meter(tx_gas_meter: &TxGasMeter) -> Self {
        Self::new_from_meter(tx_gas_meter)
    }

    /// Initialize a new VP gas meter from the given generic gas meter
    pub fn new_from_meter(gas_meter: &impl GasMetering) -> Self {
        Self {
            gas_overflow: false,
            gas_scale: gas_meter.get_gas_scale(),
            tx_gas_limit: gas_meter.get_gas_limit(),
            prev_meter_consumed_gas: gas_meter.get_consumed_gas(),
            current_gas: Gas::default(),
        }
    }

    /// Get the gas consumed by the VP alone
    pub fn get_vp_consumed_gas(&self) -> Gas {
        self.current_gas.clone()
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use proptest::prelude::*;

    use super::*;
    const BLOCK_GAS_LIMIT: u64 = 10_000_000_000;
    const TX_GAS_LIMIT: u64 = 1_000_000;
    const GAS_SCALE: u64 = 1;

    proptest! {
        #[test]
        fn test_vp_gas_meter_add(gas in 0..BLOCK_GAS_LIMIT) {
            let tx_gas_meter = TxGasMeter {
                gas_overflow: false,
                gas_scale: GAS_SCALE,
                tx_gas_limit: BLOCK_GAS_LIMIT.into(),
                transaction_gas: Gas::default(),
            };
            let mut meter = VpGasMeter::new_from_tx_meter(&tx_gas_meter);
            meter.consume(gas.into()).expect("cannot add the gas");
        }

    }

    #[test]
    fn test_vp_gas_overflow() {
        let tx_gas_meter = TxGasMeter {
            gas_overflow: false,
            gas_scale: GAS_SCALE,
            tx_gas_limit: BLOCK_GAS_LIMIT.into(),
            transaction_gas: (TX_GAS_LIMIT - 1).into(),
        };
        let mut meter = VpGasMeter::new_from_tx_meter(&tx_gas_meter);
        assert_matches!(
            meter
                .consume(u64::MAX.into())
                .expect_err("unexpectedly succeeded"),
            Error::GasOverflow
        );
    }

    #[test]
    fn test_vp_gas_limit() {
        let tx_gas_meter = TxGasMeter {
            gas_overflow: false,
            gas_scale: GAS_SCALE,
            tx_gas_limit: TX_GAS_LIMIT.into(),
            transaction_gas: (TX_GAS_LIMIT - 1).into(),
        };
        let mut meter = VpGasMeter::new_from_tx_meter(&tx_gas_meter);
        assert_matches!(
            meter
                .consume(TX_GAS_LIMIT.into())
                .expect_err("unexpectedly succeeded"),
            Error::TransactionGasExceededError(_)
        );
    }

    #[test]
    fn test_tx_gas_overflow() {
        let mut meter = TxGasMeter::new(BLOCK_GAS_LIMIT, GAS_SCALE);
        meter.consume(1.into()).expect("cannot add the gas");
        assert_matches!(
            meter
                .consume(u64::MAX.into())
                .expect_err("unexpectedly succeeded"),
            Error::GasOverflow
        );
    }

    #[test]
    fn test_tx_gas_limit() {
        let mut meter = TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE);
        assert_matches!(
            meter
                .consume((TX_GAS_LIMIT + 1).into())
                .expect_err("unexpectedly succeeded"),
            Error::TransactionGasExceededError(_)
        );
    }
}
