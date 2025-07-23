//! Parameters for configuring the Ethereum bridge
use std::num::NonZeroU64;

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ethereum_events::EthAddress;
use namada_core::ethereum_structs;
use namada_core::storage::Key;
use namada_core::token::{DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_state::{DBIter, DBRead, StorageHasher, WlState};
use namada_storage::{Error, Result, StorageRead, StorageWrite};
use serde::{Deserialize, Serialize};

use super::whitelist;
use crate::storage as bridge_storage;
use crate::storage::eth_bridge_queries::{
    EthBridgeEnabled, EthBridgeQueries, EthBridgeStatus,
};
use crate::storage::vp;

/// An ERC20 token whitelist entry.
#[derive(
    Clone,
    Copy,
    Eq,
    PartialEq,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct Erc20WhitelistEntry {
    /// The address of the whitelisted ERC20 token.
    pub token_address: EthAddress,
    /// The token cap of the whitelisted ERC20 token.
    pub token_cap: DenominatedAmount,
}

/// Represents a configuration value for the minimum number of
/// confirmations an Ethereum event must reach before it can be acted on.
#[derive(
    Clone,
    Copy,
    Eq,
    PartialEq,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
#[repr(transparent)]
pub struct MinimumConfirmations(NonZeroU64);

impl Default for MinimumConfirmations {
    fn default() -> Self {
        // SAFETY: The only way the API contract of `NonZeroU64` can be violated
        // is if we construct values of this type using 0 as argument.
        Self(unsafe { NonZeroU64::new_unchecked(100) })
    }
}

impl From<NonZeroU64> for MinimumConfirmations {
    fn from(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl From<MinimumConfirmations> for NonZeroU64 {
    fn from(value: MinimumConfirmations) -> Self {
        value.0
    }
}

/// Represents a configuration value for the version of a contract that can be
/// upgraded. Starts from 1.
#[derive(
    Clone,
    Copy,
    Eq,
    PartialEq,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
#[repr(transparent)]
pub struct ContractVersion(NonZeroU64);

impl Default for ContractVersion {
    fn default() -> Self {
        // SAFETY: The only way the API contract of `NonZeroU64` can be
        // violated is if we construct values of this type using 0 as
        // argument.
        Self(unsafe { NonZeroU64::new_unchecked(1) })
    }
}

/// Represents an Ethereum contract that may be upgraded.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct UpgradeableContract {
    /// The Ethereum address of the contract.
    pub address: EthAddress,
    /// The version of the contract. Starts from 1.
    pub version: ContractVersion,
}

/// Represents all the Ethereum contracts that need to be directly know about by
/// validators.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct Contracts {
    /// The Ethereum address of the ERC20 contract that represents this chain's
    /// native token.
    pub native_erc20: EthAddress,
    /// The Ethereum address of the bridge contract.
    pub bridge: UpgradeableContract,
}

/// Represents chain parameters for the Ethereum bridge.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct EthereumBridgeParams {
    /// Initial Ethereum block height when events will first be extracted from.
    pub eth_start_height: ethereum_structs::BlockHeight,
    /// Minimum number of confirmations needed to trust an Ethereum branch.
    /// This must be at least one.
    pub min_confirmations: MinimumConfirmations,
    /// List of ERC20 token types whitelisted at genesis time.
    pub erc20_whitelist: Vec<Erc20WhitelistEntry>,
    /// The addresses of the Ethereum contracts that need to be directly known
    /// by validators.
    pub contracts: Contracts,
}

impl EthereumBridgeParams {
    /// Initialize the Ethereum bridge parameters in storage.
    ///
    /// If these parameters are initialized, the storage subspaces
    /// for the Ethereum bridge VPs are also initialized.
    pub fn init_storage<D, H>(&self, state: &mut WlState<'_, D, H>)
    where
        D: 'static + DBRead + for<'iter> DBIter<'iter>,
        H: 'static + StorageHasher,
    {
        let Self {
            erc20_whitelist,
            eth_start_height,
            min_confirmations,
            contracts:
                Contracts {
                    native_erc20,
                    bridge,
                },
        } = self;
        let active_key = bridge_storage::active_key();
        let min_confirmations_key = bridge_storage::min_confirmations_key();
        let native_erc20_key = bridge_storage::native_erc20_key();
        let bridge_contract_key = bridge_storage::bridge_contract_key();
        let eth_start_height_key = bridge_storage::eth_start_height_key();
        state
            .write(
                &active_key,
                EthBridgeStatus::Enabled(EthBridgeEnabled::AtGenesis),
            )
            .unwrap();
        state
            .write(&min_confirmations_key, min_confirmations)
            .unwrap();
        state.write(&native_erc20_key, native_erc20).unwrap();
        state.write(&bridge_contract_key, bridge).unwrap();
        state
            .write(&eth_start_height_key, eth_start_height)
            .unwrap();
        for Erc20WhitelistEntry {
            token_address: addr,
            token_cap,
        } in erc20_whitelist
        {
            let cap = token_cap.amount();
            let denom = token_cap.denom();
            if addr == native_erc20 && denom != NATIVE_MAX_DECIMAL_PLACES.into()
            {
                panic!(
                    "Error writing Ethereum bridge config: The native token \
                     should have {NATIVE_MAX_DECIMAL_PLACES} decimal places"
                );
            }

            let key = whitelist::Key {
                asset: *addr,
                suffix: whitelist::KeyType::Whitelisted,
            }
            .into();
            state.write(&key, true).unwrap();

            let key = whitelist::Key {
                asset: *addr,
                suffix: whitelist::KeyType::Cap,
            }
            .into();
            state.write(&key, cap).unwrap();

            let key = whitelist::Key {
                asset: *addr,
                suffix: whitelist::KeyType::Denomination,
            }
            .into();
            state.write(&key, denom).unwrap();
        }
        // Initialize the storage for the Ethereum Bridge VP.
        vp::ethereum_bridge::init_storage(state);
        // Initialize the storage for the Bridge Pool VP.
        vp::bridge_pool::init_storage(state);
    }
}

/// Subset of [`EthereumBridgeParams`], containing only Ethereum
/// oracle specific parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumOracleConfig {
    /// Initial Ethereum block height when events will first be extracted from.
    pub eth_start_height: ethereum_structs::BlockHeight,
    /// Minimum number of confirmations needed to trust an Ethereum branch.
    /// This must be at least one.
    pub min_confirmations: MinimumConfirmations,
    /// The addresses of the Ethereum contracts that need to be directly known
    /// by validators.
    pub contracts: Contracts,
}

impl From<EthereumBridgeParams> for EthereumOracleConfig {
    fn from(config: EthereumBridgeParams) -> Self {
        let EthereumBridgeParams {
            eth_start_height,
            min_confirmations,
            contracts,
            ..
        } = config;
        Self {
            eth_start_height,
            min_confirmations,
            contracts,
        }
    }
}

impl EthereumOracleConfig {
    /// Reads the latest [`EthereumOracleConfig`] from storage. If it is not
    /// present, `None` will be returned - this could be the case if the bridge
    /// has not been bootstrapped yet. Panics if the storage appears to be
    /// corrupt.
    pub fn read<D, H>(state: &WlState<'_, D, H>) -> Option<Self>
    where
        D: 'static + DBRead + for<'iter> DBIter<'iter>,
        H: 'static + StorageHasher,
    {
        // TODO(namada#1720): remove present key check; `is_bridge_active`
        // should not panic, when the active status key has not been
        // written to; simply return bridge disabled instead
        let has_active_key =
            state.has_key(&bridge_storage::active_key()).unwrap();

        if !has_active_key || !state.ethbridge_queries().is_bridge_active() {
            return None;
        }

        let min_confirmations_key = bridge_storage::min_confirmations_key();
        let native_erc20_key = bridge_storage::native_erc20_key();
        let bridge_contract_key = bridge_storage::bridge_contract_key();
        let eth_start_height_key = bridge_storage::eth_start_height_key();

        // These reads must succeed otherwise the storage is corrupt or a
        // read failed
        let min_confirmations = must_read_key(state, &min_confirmations_key);
        let native_erc20 = must_read_key(state, &native_erc20_key);
        let bridge_contract = must_read_key(state, &bridge_contract_key);
        let eth_start_height = must_read_key(state, &eth_start_height_key);

        Some(Self {
            eth_start_height,
            min_confirmations,
            contracts: Contracts {
                native_erc20,
                bridge: bridge_contract,
            },
        })
    }
}

/// Get the Ethereum address for wNam from storage, if possible
pub fn read_native_erc20_address<S>(storage: &S) -> Result<EthAddress>
where
    S: StorageRead,
{
    let native_erc20 = bridge_storage::native_erc20_key();

    storage.read(&native_erc20)?.ok_or_else(|| {
        Error::SimpleMessage("The Ethereum bridge storage is not initialized")
    })
}

/// Reads the value of `key` from `storage` and deserializes it, or panics
/// otherwise.
fn must_read_key<D, H, T: BorshDeserialize>(
    state: &WlState<'_, D, H>,
    key: &Key,
) -> T
where
    D: 'static + DBRead + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    StorageRead::read::<T>(state, key).map_or_else(
        |err| panic!("Could not read {key}: {err:?}"),
        |value| {
            value.unwrap_or_else(|| {
                panic!(
                    "Ethereum bridge appears to be only partially configured! \
                     There was no value for {key}"
                )
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use namada_state::testing::TestState;
    use namada_storage::ResultExt;

    use super::*;
    use crate::storage::eth_bridge_queries::is_bridge_comptime_enabled;

    /// Ensure we can serialize and deserialize a [`Config`] struct to and from
    /// TOML. This can fail if complex fields are ordered before simple fields
    /// in any of the config structs.
    #[test]
    fn test_round_trip_toml_serde() -> Result<()> {
        let config = EthereumBridgeParams {
            erc20_whitelist: vec![],
            eth_start_height: Default::default(),
            min_confirmations: MinimumConfirmations::default(),
            contracts: Contracts {
                native_erc20: EthAddress([42; 20]),
                bridge: UpgradeableContract {
                    address: EthAddress([23; 20]),
                    version: ContractVersion::default(),
                },
            },
        };
        let serialized = toml::to_string(&config).into_storage_result()?;
        let deserialized: EthereumBridgeParams =
            toml::from_str(&serialized).into_storage_result()?;

        assert_eq!(config, deserialized);
        Ok(())
    }

    #[test]
    fn test_ethereum_bridge_config_read_write_storage() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }

        let mut state = TestState::default();
        let config = EthereumBridgeParams {
            erc20_whitelist: vec![],
            eth_start_height: Default::default(),
            min_confirmations: MinimumConfirmations::default(),
            contracts: Contracts {
                native_erc20: EthAddress([42; 20]),
                bridge: UpgradeableContract {
                    address: EthAddress([23; 20]),
                    version: ContractVersion::default(),
                },
            },
        };
        config.init_storage(&mut state);

        let read = EthereumOracleConfig::read(&state).unwrap();
        let config = EthereumOracleConfig::from(config);

        assert_eq!(config, read);
    }

    #[test]
    fn test_ethereum_bridge_config_uninitialized() {
        let state = TestState::default();
        let read = EthereumOracleConfig::read(&state);

        assert!(read.is_none());
    }

    #[test]
    #[cfg_attr(not(feature = "namada-eth-bridge"), ignore)]
    #[should_panic(expected = "Could not read")]
    fn test_ethereum_bridge_config_storage_corrupt() {
        let mut state = TestState::default();
        let config = EthereumBridgeParams {
            erc20_whitelist: vec![],
            eth_start_height: Default::default(),
            min_confirmations: MinimumConfirmations::default(),
            contracts: Contracts {
                native_erc20: EthAddress([42; 20]),
                bridge: UpgradeableContract {
                    address: EthAddress([23; 20]),
                    version: ContractVersion::default(),
                },
            },
        };
        config.init_storage(&mut state);
        let min_confirmations_key = bridge_storage::min_confirmations_key();
        state
            .write(&min_confirmations_key, vec![42, 1, 2, 3, 4])
            .unwrap();

        // This should panic because the min_confirmations value is not valid
        EthereumOracleConfig::read(&state);
    }

    #[test]
    #[cfg_attr(not(feature = "namada-eth-bridge"), ignore)]
    #[should_panic(
        expected = "Ethereum bridge appears to be only partially configured!"
    )]
    fn test_ethereum_bridge_config_storage_partially_configured() {
        let mut state = TestState::default();
        state
            .write(
                &bridge_storage::active_key(),
                EthBridgeStatus::Enabled(EthBridgeEnabled::AtGenesis),
            )
            .unwrap();
        // Write a valid min_confirmations value
        state
            .write(
                &bridge_storage::min_confirmations_key(),
                MinimumConfirmations::default(),
            )
            .unwrap();

        // This should panic as the other config values are not written
        EthereumOracleConfig::read(&state);
    }
}
