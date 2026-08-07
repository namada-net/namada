//! Parameters abstract interfaces

use namada_core::address::Address;
use namada_core::chain::{BlockHeight, Epoch};
use namada_core::dec::Dec;
use namada_core::masp::MaspEpoch;
pub use namada_core::parameters::*;
use namada_core::storage;
use namada_core::time::DurationSecs;
pub use namada_storage::Result;

/// Abstract parameters storage keys interface
pub trait Keys {
    /// Key for implicit VP
    fn implicit_vp_key() -> storage::Key;
}

/// Abstract parameters storage read interface
pub trait Read<S> {
    /// Read all parameters
    fn read(storage: &S) -> Result<Parameters>;

    /// Read MASP epoch multiplier parameter
    fn masp_epoch_multiplier(storage: &S) -> Result<u64>;

    /// Read the the epoch duration parameter
    fn epoch_duration_parameter(storage: &S) -> Result<EpochDuration>;

    /// Read the `is_native_token_transferable` parameter
    fn is_native_token_transferable(storage: &S) -> Result<bool>;

    /// Read the number of epochs per year parameter
    fn epochs_per_year(storage: &S) -> Result<u64>;

    /// Return an estimate of the maximum time taken to decide a block,
    /// by sourcing block headers from up to `num_blocks_to_read`, and
    /// from chain parameters.
    fn estimate_max_block_time_from_blocks_and_params(
        storage: &S,
        last_block_height: BlockHeight,
        num_blocks_to_read: u64,
    ) -> Result<DurationSecs>;

    /// Read the current MASP epoch
    fn masp_epoch(storage: &S, current_epoch: Epoch) -> Result<MaspEpoch> {
        MaspEpoch::try_from_epoch(
            current_epoch,
            Self::masp_epoch_multiplier(storage)?,
        )
        .map_err(namada_storage::Error::SimpleMessage)
    }

    /// Read the shielding fee percentage over IBC of the token with address
    /// `token_addr`.
    fn ibc_shielding_fee_percentage(
        storage: &S,
        token: &Address,
    ) -> Result<Option<Dec>>;

    /// Read the unshielding fee percentage over IBC of the token with address
    /// `token_addr`.
    fn ibc_unshielding_fee_percentage(
        storage: &S,
        token: &Address,
    ) -> Result<Option<Dec>>;
}

/// Abstract parameters storage write interface
pub trait Write<S>: Read<S> {
    /// Write all parameters
    fn write(storage: &mut S, parameters: &Parameters) -> Result<()>;
}
