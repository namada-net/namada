//! One-off MASP rewards reset, run in `FinalizeBlock` at the block height set
//! in [`RESET_HEIGHT_ENV`].
//!
//! Every validator must set the same height, otherwise they will disagree on
//! the state at that height.

use std::sync::OnceLock;

use namada_sdk::chain::{BlockHeight, Epoch};
use namada_sdk::parameters;
use namada_sdk::state::{Result, StorageRead, StorageWrite};
use namada_sdk::token::{self, MaspEpoch, WithConversionState};

/// Env var with the block height at which the reset runs
pub const RESET_HEIGHT_ENV: &str = "NAMADA_MASP_REWARDS_RESET_HEIGHT";

/// The epoch (inclusive) from which the reset strips the published rewards
/// out of the conversions. Rewards published before it are kept.
pub const RESET_FROM_EPOCH: Epoch = Epoch(2244);

/// Run the reset if `height` is the reset height set in [`RESET_HEIGHT_ENV`]
pub fn reset_at_height<S>(storage: &mut S, height: BlockHeight) -> Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
{
    reset_if_scheduled(storage, height, reset_height())
}

/// Run the reset if `height` is the `scheduled` reset height
fn reset_if_scheduled<S>(
    storage: &mut S,
    height: BlockHeight,
    scheduled: Option<BlockHeight>,
) -> Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
{
    if scheduled != Some(height) {
        return Ok(());
    }
    let masp_epoch_multiplier =
        parameters::read_masp_epoch_multiplier_parameter(storage)?;
    let reset_from = reset_from_masp_epoch(masp_epoch_multiplier);
    tracing::warn!(
        "Block height {height}: resetting MASP rewards and stripping the \
         rewards published from MASP epoch {reset_from} on"
    );
    token::rewards_reset::reset_masp_rewards_and_conversions::<
        S,
        token::Store<()>,
    >(storage, reset_from)
}

/// The block height at which the reset runs, read once from
/// [`RESET_HEIGHT_ENV`]
fn reset_height() -> Option<BlockHeight> {
    static RESET_HEIGHT: OnceLock<Option<BlockHeight>> = OnceLock::new();
    *RESET_HEIGHT.get_or_init(|| {
        let height =
            parse_reset_height(std::env::var(RESET_HEIGHT_ENV).ok().as_deref());
        if let Some(height) = height {
            tracing::info!("MASP rewards reset scheduled at height {height}");
        }
        height
    })
}

/// Parse the reset height from the env var value, if any. Panics on an
/// invalid value rather than silently skipping the reset.
fn parse_reset_height(value: Option<&str>) -> Option<BlockHeight> {
    value.map(|value| {
        let height = value.trim().parse::<u64>().unwrap_or_else(|err| {
            panic!("Invalid {RESET_HEIGHT_ENV} value {value:?}: {err}")
        });
        BlockHeight(height)
    })
}

/// The MASP epoch containing [`RESET_FROM_EPOCH`]
fn reset_from_masp_epoch(masp_epoch_multiplier: u64) -> MaspEpoch {
    MaspEpoch::try_from_epoch(RESET_FROM_EPOCH, masp_epoch_multiplier)
        .expect("MASP epoch multiplier must not be 0")
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use namada_sdk::address::{Address, MASP};
    use namada_sdk::dec::Dec;
    use namada_sdk::hash::Hash;
    use namada_sdk::state::ReadConversionState;
    use namada_sdk::token::Amount;
    use namada_sdk::token::storage_key::{
        balance_key, masp_assets_hash_key, masp_convert_anchor_key,
        masp_max_reward_rate_key, masp_token_map_key,
    };

    use super::*;
    use crate::shell::test_utils::{self, TestShell};

    const RESET_HEIGHT: BlockHeight = BlockHeight(100);

    fn masp_tokens(shell: &TestShell) -> Vec<Address> {
        let token_map: BTreeMap<String, Address> =
            shell.state.read(&masp_token_map_key()).unwrap().unwrap();
        token_map.into_values().collect()
    }

    fn max_reward_rate(shell: &TestShell, token: &Address) -> Dec {
        shell
            .state
            .read(&masp_max_reward_rate_key(token))
            .unwrap()
            .unwrap()
    }

    fn convert_anchor(shell: &TestShell) -> Hash {
        shell
            .state
            .read(&masp_convert_anchor_key())
            .unwrap()
            .unwrap()
    }

    fn assets_hash(shell: &TestShell) -> Hash {
        shell.state.read(&masp_assets_hash_key()).unwrap().unwrap()
    }

    /// A shell whose MASP holds some of every reward token, with conversions
    /// published for the MASP epochs before, at and after the one containing
    /// [`RESET_FROM_EPOCH`]. The native token earns no rewards, as on mainnet.
    fn shell_with_conversions() -> TestShell {
        let (mut shell, ..) = test_utils::setup();
        let native_token = shell.state.get_native_token().unwrap();
        shell
            .state
            .write(&masp_max_reward_rate_key(&native_token), Dec::zero())
            .unwrap();
        for token in masp_tokens(&shell) {
            shell
                .state
                .write(
                    &balance_key(&token, &MASP),
                    Amount::from_u64(1_000_000_000_000),
                )
                .unwrap();
        }
        let multiplier =
            parameters::read_masp_epoch_multiplier_parameter(&shell.state)
                .unwrap();
        for epoch in [
            RESET_FROM_EPOCH.0 - multiplier,
            RESET_FROM_EPOCH.0,
            RESET_FROM_EPOCH.0 + multiplier,
        ] {
            shell.state.in_mem_mut().block.epoch = Epoch(epoch);
            token::conversion::update_allowed_conversions::<
                _,
                parameters::Store<_>,
                token::Store<_>,
            >(&mut shell.state)
            .unwrap();
        }
        shell
    }

    /// Nothing happens when no reset is scheduled or at any other height.
    #[test]
    fn test_reset_skipped_when_not_scheduled() {
        let mut shell = shell_with_conversions();
        let tokens = masp_tokens(&shell);
        let rates: Vec<_> =
            tokens.iter().map(|t| max_reward_rate(&shell, t)).collect();
        assert!(rates.iter().any(|rate| *rate != Dec::zero()));
        let anchor = convert_anchor(&shell);
        let hash = assets_hash(&shell);

        for (height, scheduled) in [
            (RESET_HEIGHT, None),
            (RESET_HEIGHT.prev_height().unwrap(), Some(RESET_HEIGHT)),
            (RESET_HEIGHT.next_height(), Some(RESET_HEIGHT)),
        ] {
            reset_if_scheduled(&mut shell.state, height, scheduled).unwrap();

            let rates_after: Vec<_> =
                tokens.iter().map(|t| max_reward_rate(&shell, t)).collect();
            assert_eq!(rates_after, rates);
            assert_eq!(convert_anchor(&shell), anchor);
            assert_eq!(assets_hash(&shell), hash);
        }
    }

    /// At the scheduled height the reward rates are zeroed and the stored
    /// anchor and assets hash match the rewritten conversion state.
    #[test]
    fn test_reset_runs_at_scheduled_height() {
        use namada_sdk::borsh::BorshSerializeExt;

        let mut shell = shell_with_conversions();
        let anchor = convert_anchor(&shell);

        reset_if_scheduled(&mut shell.state, RESET_HEIGHT, Some(RESET_HEIGHT))
            .unwrap();

        for token in masp_tokens(&shell) {
            assert_eq!(max_reward_rate(&shell, &token), Dec::zero());
        }
        let state = shell.state.conversion_state();
        assert_eq!(state.tree.size(), state.assets.len());
        assert_ne!(convert_anchor(&shell), anchor);
        assert_eq!(
            assets_hash(&shell),
            Hash::sha256(state.assets.serialize_to_vec())
        );
    }

    /// Running the reset on two identical states gives identical results.
    #[test]
    fn test_reset_is_deterministic() {
        let mut results = vec![];
        for _ in 0..2 {
            let mut shell = shell_with_conversions();
            reset_if_scheduled(
                &mut shell.state,
                RESET_HEIGHT,
                Some(RESET_HEIGHT),
            )
            .unwrap();
            results.push((convert_anchor(&shell), assets_hash(&shell)));
        }
        assert_eq!(results[0], results[1]);
    }

    /// With mainnet's MASP epoch multiplier of 4, epoch 2244 is the first
    /// epoch of MASP epoch 561.
    #[test]
    fn test_reset_from_masp_epoch() {
        assert_eq!(
            reset_from_masp_epoch(4),
            MaspEpoch::try_from_epoch(Epoch(561), 1).unwrap()
        );
    }

    /// The reset height is only set when the env var is present and must be
    /// a valid block height.
    #[test]
    fn test_parse_reset_height() {
        assert_eq!(parse_reset_height(None), None);
        assert_eq!(
            parse_reset_height(Some("8517987")),
            Some(BlockHeight(8517987))
        );
        assert_eq!(parse_reset_height(Some(" 42\n")), Some(BlockHeight(42)));
        assert!(
            std::panic::catch_unwind(|| parse_reset_height(Some("nope")))
                .is_err()
        );
    }
}
