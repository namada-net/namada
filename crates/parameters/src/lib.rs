//! Protocol parameters

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
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

pub mod storage;
pub mod vp;
mod wasm_allowlist;
use std::collections::BTreeMap;
use std::marker::PhantomData;

use namada_core::address::{Address, InternalAddress};
use namada_core::arith::checked;
use namada_core::chain::BlockHeight;
use namada_core::dec::Dec;
pub use namada_core::parameters::ProposalBytes;
use namada_core::time::DurationSecs;
use namada_core::{hints, token};
use namada_state::{Error, Key, ResultExt, StorageRead, StorageWrite};
pub use namada_systems::parameters::*;
pub use storage::{get_gas_scale, get_max_block_gas};
use thiserror::Error;
pub use wasm_allowlist::{is_tx_allowed, is_vp_allowed};

/// Parameters storage `Keys/Read/Write` implementation
#[derive(Debug)]
pub struct Store<S>(PhantomData<S>);

impl<S> Keys for Store<S> {
    fn implicit_vp_key() -> Key {
        storage::get_implicit_vp_key()
    }
}

impl<S> Read<S> for Store<S>
where
    S: StorageRead,
{
    fn read(storage: &S) -> Result<Parameters> {
        read(storage)
    }

    fn masp_epoch_multiplier(storage: &S) -> Result<u64> {
        read_masp_epoch_multiplier_parameter(storage)
    }

    fn epoch_duration_parameter(storage: &S) -> Result<EpochDuration> {
        read_epoch_duration_parameter(storage)
    }

    fn is_native_token_transferable(storage: &S) -> Result<bool> {
        storage::is_native_token_transferable(storage)
    }

    fn epochs_per_year(storage: &S) -> Result<u64> {
        read_epochs_per_year(storage)
    }

    fn estimate_max_block_time_from_blocks_and_params(
        storage: &S,
        last_block_height: BlockHeight,
        num_blocks_to_read: u64,
    ) -> Result<DurationSecs> {
        estimate_max_block_time_from_blocks_and_params(
            storage,
            last_block_height,
            num_blocks_to_read,
        )
    }

    fn ibc_shielding_fee_percentage(
        storage: &S,
        token: &Address,
    ) -> Result<Option<Dec>> {
        storage::read_masp_over_ibc_shielding_fee(storage, token)
    }

    fn ibc_unshielding_fee_percentage(
        storage: &S,
        token: &Address,
    ) -> Result<Option<Dec>> {
        storage::read_masp_over_ibc_unshielding_fee(storage, token)
    }
}

impl<S> Write<S> for Store<S>
where
    S: StorageRead + StorageWrite,
{
    fn write(storage: &mut S, parameters: &Parameters) -> Result<()> {
        init_storage(parameters, storage)
    }
}

/// The internal address for storage keys representing parameters than
/// can be changed via governance.
pub const ADDRESS: Address = Address::Internal(InternalAddress::Parameters);

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("Storage error: {0}")]
    Error(Error),
    #[error("Storage type error: {0}")]
    StorageTypeError(namada_core::storage::Error),
    #[error("Protocol parameters are missing, they must be always set")]
    ParametersMissing,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum WriteError {
    #[error("Storage error: {0}")]
    Error(Error),
    #[error("Serialize error: {0}")]
    SerializeError(String),
}

/// Initialize parameters in storage in the genesis block.
pub fn init_storage<S>(parameters: &Parameters, storage: &mut S) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let Parameters {
        max_tx_bytes,
        epoch_duration,
        max_proposal_bytes,
        max_block_gas,
        vp_allowlist,
        tx_allowlist,
        implicit_vp_code_hash,
        epochs_per_year,
        masp_epoch_multiplier,
        minimum_gas_price,
        masp_fee_payment_gas_limit,
        gas_scale,
        is_native_token_transferable,
    } = parameters;

    // write max tx bytes parameter
    let max_tx_bytes_key = storage::get_max_tx_bytes_key();
    storage.write(&max_tx_bytes_key, max_tx_bytes)?;

    // write max proposal bytes parameter
    let max_proposal_bytes_key = storage::get_max_proposal_bytes_key();
    storage.write(&max_proposal_bytes_key, max_proposal_bytes)?;

    // write max block gas parameter
    let max_block_gas_key = storage::get_max_block_gas_key();
    storage.write(&max_block_gas_key, max_block_gas)?;

    // write epoch parameters
    let epoch_key = storage::get_epoch_duration_storage_key();
    storage.write(&epoch_key, epoch_duration)?;

    // write masp fee payment gas limit
    let masp_fee_payment_gas_limit_key =
        storage::get_masp_fee_payment_gas_limit_key();
    storage
        .write(&masp_fee_payment_gas_limit_key, masp_fee_payment_gas_limit)?;

    // write the gas scale
    let gas_scale_key = storage::get_gas_scale_key();
    storage.write(&gas_scale_key, gas_scale)?;

    // write vp allowlist parameter
    let vp_allowlist_key = storage::get_vp_allowlist_storage_key();
    let vp_allowlist = vp_allowlist
        .iter()
        .map(|id| id.to_lowercase())
        .collect::<Vec<String>>();
    storage.write(&vp_allowlist_key, vp_allowlist)?;

    // write tx allowlist parameter
    let tx_allowlist_key = storage::get_tx_allowlist_storage_key();
    let tx_allowlist = tx_allowlist
        .iter()
        .map(|id| id.to_lowercase())
        .collect::<Vec<String>>();
    storage.write(&tx_allowlist_key, tx_allowlist)?;

    // write implicit vp parameter
    let implicit_vp_key = storage::get_implicit_vp_key();
    // Using `fn write_bytes` here, because implicit_vp code hash doesn't
    // need to be encoded, it's bytes already.
    storage
        .write(&implicit_vp_key, implicit_vp_code_hash.unwrap_or_default())?;

    let epochs_per_year_key = storage::get_epochs_per_year_key();
    storage.write(&epochs_per_year_key, epochs_per_year)?;

    let masp_epoch_multiplier_key = storage::get_masp_epoch_multiplier_key();
    storage.write(&masp_epoch_multiplier_key, masp_epoch_multiplier)?;

    let gas_cost_key = storage::get_gas_cost_key();
    storage.write(&gas_cost_key, minimum_gas_price)?;

    let native_token_transferable_key =
        storage::get_native_token_transferable_key();
    storage
        .write(&native_token_transferable_key, is_native_token_transferable)?;

    Ok(())
}

/// Update the vp allowlist parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_vp_allowlist_parameter<S>(
    storage: &mut S,
    value: Vec<String>,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_vp_allowlist_storage_key();
    storage.write(
        &key,
        value
            .iter()
            .map(|id| id.to_lowercase())
            .collect::<Vec<String>>(),
    )
}

/// Update the tx allowlist parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_tx_allowlist_parameter<S>(
    storage: &mut S,
    value: Vec<String>,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_tx_allowlist_storage_key();
    storage.write(
        &key,
        value
            .iter()
            .map(|id| id.to_lowercase())
            .collect::<Vec<String>>(),
    )
}

/// Update the epoch parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_epoch_parameter<S>(
    storage: &mut S,
    value: &EpochDuration,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_epoch_duration_storage_key();
    storage.write(&key, value)
}

/// Update the epochs_per_year parameter in storage. Returns the parameters and
/// gas cost.
pub fn update_epochs_per_year_parameter<S>(
    storage: &mut S,
    value: &u64,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_epochs_per_year_key();
    storage.write(&key, value)
}

/// Update the implicit VP parameter in storage. Return the gas cost.
pub fn update_implicit_vp<S>(storage: &mut S, implicit_vp: &[u8]) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_implicit_vp_key();
    // Using `fn write_bytes` here, because implicit_vp doesn't need to be
    // encoded, it's bytes already.
    storage.write(&key, implicit_vp)
}

/// Read the epochs per year parameter from store
pub fn read_epochs_per_year_parameter<S>(storage: &S) -> Result<u64>
where
    S: StorageRead,
{
    let key = storage::get_epochs_per_year_key();
    let epochs_per_year = storage.read(&key)?;
    epochs_per_year
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()
}

/// Read the epoch duration parameter from store
pub fn read_epoch_duration_parameter<S>(storage: &S) -> Result<EpochDuration>
where
    S: StorageRead,
{
    // read epoch
    let epoch_key = storage::get_epoch_duration_storage_key();
    let epoch_duration = storage.read(&epoch_key)?;
    epoch_duration
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()
}

/// Read the masp epoch multiplier parameter from store
pub fn read_masp_epoch_multiplier_parameter<S>(storage: &S) -> Result<u64>
where
    S: StorageRead,
{
    // read multiplier
    let masp_epoch_multiplier_key = storage::get_masp_epoch_multiplier_key();
    let epoch_multiplier = storage.read(&masp_epoch_multiplier_key)?;
    epoch_multiplier
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()
}

/// Read the cost per unit of gas for the provided token
pub fn read_gas_cost<S>(
    storage: &S,
    token: &Address,
) -> Result<Option<token::Amount>>
where
    S: StorageRead,
{
    let gas_cost_table: BTreeMap<Address, token::Amount> = storage
        .read(&storage::get_gas_cost_key())?
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;
    Ok(gas_cost_table.get(token).map(|amount| amount.to_owned()))
}

/// Read the number of epochs per year parameter
pub fn read_epochs_per_year<S>(storage: &S) -> Result<u64>
where
    S: StorageRead,
{
    let key = storage::get_epochs_per_year_key();
    let epochs_per_year = storage.read(&key)?;
    epochs_per_year
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()
}

/// Retrieve the `max_proposal_bytes` consensus parameter from storage.
pub fn read_max_proposal_bytes<S>(storage: &S) -> Result<ProposalBytes>
where
    S: StorageRead,
{
    let key = storage::get_max_proposal_bytes_key();
    let result = storage.read(&key)?;
    result
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()
}

/// Read all the parameters from storage. Returns the parameters and gas
/// cost.
pub fn read<S>(storage: &S) -> Result<Parameters>
where
    S: StorageRead,
{
    // read max proposal bytes
    let max_proposal_bytes: ProposalBytes = {
        let key = storage::get_max_proposal_bytes_key();
        let value = storage.read(&key)?;
        value
            .ok_or(ReadError::ParametersMissing)
            .into_storage_result()?
    };

    // read max block gas
    let max_block_gas: u64 = {
        let key = storage::get_max_block_gas_key();
        let value = storage.read(&key)?;
        value
            .ok_or(ReadError::ParametersMissing)
            .into_storage_result()?
    };

    // read epoch duration
    let epoch_duration = read_epoch_duration_parameter(storage)?;

    // read vp allowlist
    let vp_allowlist_key = storage::get_vp_allowlist_storage_key();
    let value = storage.read(&vp_allowlist_key)?;
    let vp_allowlist: Vec<String> = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read tx allowlist
    let tx_allowlist_key = storage::get_tx_allowlist_storage_key();
    let value = storage.read(&tx_allowlist_key)?;
    let tx_allowlist: Vec<String> = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    let implicit_vp_key = storage::get_implicit_vp_key();
    let implicit_vp_code_hash = storage
        .read(&implicit_vp_key)?
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read masp fee payment gas limit
    let masp_fee_payment_gas_limit_key =
        storage::get_masp_fee_payment_gas_limit_key();
    let value = storage.read(&masp_fee_payment_gas_limit_key)?;
    let masp_fee_payment_gas_limit: u64 = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read gas scale
    let gas_scale_key = storage::get_gas_scale_key();
    let value = storage.read(&gas_scale_key)?;
    let gas_scale: u64 = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read epochs per year
    let epochs_per_year_key = storage::get_epochs_per_year_key();
    let value = storage.read(&epochs_per_year_key)?;
    let epochs_per_year: u64 = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read masp epoch multiplier
    let masp_epoch_multiplier = read_masp_epoch_multiplier_parameter(storage)?;

    // read gas cost
    let gas_cost_key = storage::get_gas_cost_key();
    let value = storage.read(&gas_cost_key)?;
    let minimum_gas_price: BTreeMap<Address, token::Amount> = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read max tx bytes
    let max_tx_bytes_key = storage::get_max_tx_bytes_key();
    let value = storage.read(&max_tx_bytes_key)?;
    let max_tx_bytes = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    let native_token_transferable_key =
        storage::get_native_token_transferable_key();
    let value = storage.read(&native_token_transferable_key)?;
    let is_native_token_transferable = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    Ok(Parameters {
        max_tx_bytes,
        epoch_duration,
        max_proposal_bytes,
        max_block_gas,
        vp_allowlist,
        tx_allowlist,
        implicit_vp_code_hash: Some(implicit_vp_code_hash),
        epochs_per_year,
        masp_epoch_multiplier,
        minimum_gas_price,
        masp_fee_payment_gas_limit,
        gas_scale,
        is_native_token_transferable,
    })
}

/// Validate the size of a tx.
pub fn validate_tx_bytes<S>(storage: &S, tx_size: usize) -> Result<bool>
where
    S: StorageRead,
{
    let max_tx_bytes: u32 = storage
        .read(&storage::get_max_tx_bytes_key())?
        .expect("The max tx bytes param should be present in storage");
    Ok(tx_size <= max_tx_bytes as usize)
}

/// Storage key for the Ethereum address of wNam.
pub fn native_erc20_key() -> storage::Key {
    storage::get_native_erc20_key_at_addr(ADDRESS)
}

/// Initialize parameters to the storage for testing
#[cfg(any(test, feature = "testing"))]
pub fn init_test_storage<S>(storage: &mut S) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let params = Parameters {
        max_tx_bytes: 1024 * 1024,
        epoch_duration: EpochDuration {
            min_num_of_blocks: 1,
            min_duration: DurationSecs(3600),
        },
        max_proposal_bytes: Default::default(),
        max_block_gas: 100,
        vp_allowlist: vec![],
        tx_allowlist: vec![],
        implicit_vp_code_hash: Default::default(),
        epochs_per_year: 365,
        masp_epoch_multiplier: 2,
        masp_fee_payment_gas_limit: 0,
        gas_scale: 10_000_000,
        minimum_gas_price: Default::default(),
        is_native_token_transferable: true,
    };
    init_storage(&params, storage)
}

const BLOCK_TIME_ESTIMATE_UPPER_BOUND: DurationSecs = DurationSecs(60);

/// Return an estimate of the maximum time taken to decide a block,
/// by sourcing block headers from up to `num_blocks_to_read`.
pub fn estimate_max_block_time_from_blocks<S>(
    storage: &S,
    last_block_height: BlockHeight,
    num_blocks_to_read: u64,
) -> Result<Option<DurationSecs>>
where
    S: StorageRead,
{
    let ending_height = last_block_height.0;
    let beginning_height = ending_height.saturating_sub(
        num_blocks_to_read
            .min(last_block_height.0)
            .saturating_sub(1),
    );

    let block_timestamps = {
        let mut ts = Vec::with_capacity(
            usize::try_from({
                // NB: cap the allocation to 16
                num_blocks_to_read.min(16)
            })
            .into_storage_result()?,
        );

        for height in beginning_height..=ending_height {
            let Some(block_header) =
                storage.get_block_header(BlockHeight(height))?
            else {
                break;
            };
            ts.push(block_header.time);
        }

        ts
    };

    Ok(block_timestamps
        .windows(2)
        // NB: compute block time
        .map(|ts| {
            #[allow(clippy::arithmetic_side_effects)]
            {
                ts[1] - ts[0]
            }
        })
        .max()
        .map(|block_time| {
            block_time.clamp(DurationSecs(1), BLOCK_TIME_ESTIMATE_UPPER_BOUND)
        }))
}

/// Return an estimate of the maximum time taken to decide a block,
/// based on chain parameters.
pub fn estimate_max_block_time_from_parameters<S>(
    storage: &S,
) -> Result<DurationSecs>
where
    S: StorageRead,
{
    let EpochDuration {
        min_num_of_blocks,
        min_duration: DurationSecs(min_duration),
    } = read_epoch_duration_parameter(storage)?;

    let block_time =
        checked!(min_duration / min_num_of_blocks).into_storage_result()?;

    // NB: fallback to one block per epoch
    // if the time to decide a block is zero
    let block_time = DurationSecs(if hints::unlikely(block_time == 0) {
        min_duration
    } else {
        block_time
    });

    Ok(block_time.clamp(DurationSecs(1), BLOCK_TIME_ESTIMATE_UPPER_BOUND))
}

/// Return an estimate of the maximum time taken to decide a block,
/// by sourcing block headers from up to `num_blocks_to_read`, and
/// from chain parameters.
pub fn estimate_max_block_time_from_blocks_and_params<S>(
    storage: &S,
    last_block_height: BlockHeight,
    num_blocks_to_read: u64,
) -> Result<DurationSecs>
where
    S: StorageRead,
{
    let maybe_max_block_time = estimate_max_block_time_from_blocks(
        storage,
        last_block_height,
        num_blocks_to_read,
    )?;

    maybe_max_block_time
        .map_or_else(|| estimate_max_block_time_from_parameters(storage), Ok)
}

#[cfg(test)]
mod tests {
    use namada_core::chain::BlockHeader;
    use namada_core::time::DateTimeUtc;
    use namada_state::testing::TestStorage;

    use super::*;

    #[test]
    fn test_estimate_max_block_time_from_parameters_lower_bound() {
        let mut storage = TestStorage::default();

        update_epoch_parameter(
            &mut storage,
            &EpochDuration {
                min_duration: DurationSecs(0),
                min_num_of_blocks: 5,
            },
        )
        .unwrap();

        let max_block_time =
            estimate_max_block_time_from_parameters(&storage).unwrap();

        assert_eq!(max_block_time, DurationSecs(1));
    }

    #[test]
    fn test_estimate_max_block_time_from_parameters_upper_bound() {
        let mut storage = TestStorage::default();

        update_epoch_parameter(
            &mut storage,
            &EpochDuration {
                min_duration: DurationSecs(1200),
                min_num_of_blocks: 2,
            },
        )
        .unwrap();

        let max_block_time =
            estimate_max_block_time_from_parameters(&storage).unwrap();

        assert_eq!(max_block_time, BLOCK_TIME_ESTIMATE_UPPER_BOUND);
    }

    #[test]
    fn test_estimate_max_block_time_from_parameters() {
        let mut storage = TestStorage::default();

        update_epoch_parameter(
            &mut storage,
            &EpochDuration {
                min_duration: DurationSecs(10),
                min_num_of_blocks: 5,
            },
        )
        .unwrap();

        let max_block_time =
            estimate_max_block_time_from_parameters(&storage).unwrap();

        assert_eq!(max_block_time, DurationSecs(2));
    }

    #[test]
    fn test_estimate_max_block_time_from_parameters_short_epoch() {
        let mut storage = TestStorage::default();

        update_epoch_parameter(
            &mut storage,
            &EpochDuration {
                min_duration: DurationSecs(4),
                min_num_of_blocks: 5,
            },
        )
        .unwrap();

        let max_block_time =
            estimate_max_block_time_from_parameters(&storage).unwrap();

        assert_eq!(max_block_time, DurationSecs(4));
    }

    #[test]
    fn test_estimate_max_block_time_from_blocks() {
        let mut storage = TestStorage::default();

        for i in 1i64..10 {
            let height = BlockHeight(u64::try_from(i).unwrap());
            let timestamp = checked!((10i64 + i) * i).unwrap();

            storage.set_mock_block_header(
                height,
                BlockHeader {
                    time: DateTimeUtc::from_unix_timestamp(timestamp).unwrap(),
                    ..Default::default()
                },
            );
        }

        let max_block_time =
            estimate_max_block_time_from_blocks(&storage, 9.into(), 5).unwrap();

        assert_eq!(max_block_time, Some(DurationSecs(27)));
    }

    #[test]
    fn test_estimate_max_block_time_from_blocks_read_past_limit() {
        let mut storage = TestStorage::default();

        for i in 1i64..10 {
            let height = BlockHeight(u64::try_from(i).unwrap());
            let timestamp = checked!((10i64 + i) * i).unwrap();

            storage.set_mock_block_header(
                height,
                BlockHeader {
                    time: DateTimeUtc::from_unix_timestamp(timestamp).unwrap(),
                    ..Default::default()
                },
            );
        }

        let max_block_time =
            estimate_max_block_time_from_blocks(&storage, 9.into(), u64::MAX)
                .unwrap();

        assert_eq!(max_block_time, Some(DurationSecs(27)));
    }

    #[test]
    fn test_estimate_max_block_time_from_blocks_and_params() {
        let mut storage = TestStorage::default();

        update_epoch_parameter(
            &mut storage,
            &EpochDuration {
                min_duration: DurationSecs(10),
                min_num_of_blocks: 5,
            },
        )
        .unwrap();

        for i in 1i64..10 {
            let height = BlockHeight(u64::try_from(i).unwrap());
            let timestamp = checked!((10i64 + i) * i).unwrap();

            storage.set_mock_block_header(
                height,
                BlockHeader {
                    time: DateTimeUtc::from_unix_timestamp(timestamp).unwrap(),
                    ..Default::default()
                },
            );
        }

        let max_block_time = estimate_max_block_time_from_blocks_and_params(
            &storage,
            9.into(),
            5,
        )
        .unwrap();

        assert_eq!(max_block_time, DurationSecs(27));
    }

    #[test]
    fn test_estimate_max_block_time_from_blocks_lower_bound() {
        let mut storage = TestStorage::default();

        for height in 1u64..=2 {
            storage.set_mock_block_header(
                BlockHeight(height),
                BlockHeader {
                    time: DateTimeUtc::unix_epoch(),
                    ..Default::default()
                },
            );
        }

        let max_block_time =
            estimate_max_block_time_from_blocks(&storage, 2.into(), 2).unwrap();

        assert_eq!(max_block_time, Some(DurationSecs(1)));
    }

    #[test]
    fn test_estimate_max_block_time_from_blocks_upper_bound() {
        let mut storage = TestStorage::default();

        for i in 1i64..10 {
            let height = BlockHeight(u64::try_from(i).unwrap());
            let timestamp = checked!((400i64 + i) * i).unwrap();

            storage.set_mock_block_header(
                height,
                BlockHeader {
                    time: DateTimeUtc::from_unix_timestamp(timestamp).unwrap(),
                    ..Default::default()
                },
            );
        }

        let max_block_time =
            estimate_max_block_time_from_blocks(&storage, 9.into(), 5).unwrap();

        assert_eq!(max_block_time, Some(BLOCK_TIME_ESTIMATE_UPPER_BOUND));
    }
}
