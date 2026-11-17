//! One-off reset of the MASP rewards.
//!
//! Stops all shielded rewards and strips the rewards published from a given
//! MASP epoch on out of every conversion, keeping the ones published before.

use std::collections::BTreeMap;

use masp_primitives::asset_type::AssetType;
use masp_primitives::ff::PrimeField;
use masp_primitives::merkle_tree::FrozenCommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::I128Sum;
use namada_core::address::Address;
use namada_core::arith::{CheckedAdd, CheckedSub, checked};
use namada_core::dec::Dec;
use namada_core::masp::{MaspEpoch, TokenMap, encode_reward_asset_types};
use namada_core::token::{Amount, Denomination, MaspDigitPos};
use namada_systems::trans_token;

use crate::conversion::{write_assets_hash, write_convert_anchor};
use crate::storage_key::{
    masp_last_inflation_key, masp_max_reward_rate_key, masp_token_map_key,
};
use crate::{
    ConversionState, Error, OptionExt, Result, ResultExt, StorageRead,
    StorageWrite, WithConversionState,
};

/// What [`strip_rewards`] did to the conversion leaves
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StripStats {
    /// Leaves that had some rewards removed
    pub stripped: usize,
    /// Leaves left unchanged
    pub unchanged: usize,
}

/// Reset the MASP rewards and strip the rewards published at MASP epoch
/// `reset_from` or later out of every conversion.
///
/// - Sets the max reward rate and the last inflation of every token in the MASP
///   token map to zero, so no further shielded rewards are computed.
/// - Strips the rewards out of the conversion leaves, see [`strip_rewards`].
/// - Rebuilds the conversion tree and writes the new convert anchor and assets
///   hash.
///
/// Notes of any epoch stay spendable and convertible to the latest epoch.
pub fn reset_masp_rewards_and_conversions<S, TransToken>(
    storage: &mut S,
    reset_from: MaspEpoch,
) -> Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
    TransToken: trans_token::Keys,
{
    zero_reward_params::<S, TransToken>(storage)?;

    let native_token = storage.get_native_token()?;
    let stats = strip_rewards(
        storage.conversion_state_mut(),
        &native_token,
        reset_from,
    )?;
    rebuild_conversion_tree(storage.conversion_state_mut());
    write_convert_anchor(storage)?;
    write_assets_hash(storage)?;

    tracing::info!(
        "MASP rewards reset from MASP epoch {reset_from}: rewards stripped \
         from {} conversions, {} unchanged",
        stats.stripped,
        stats.unchanged,
    );
    Ok(())
}

/// Set the max reward rate and the last inflation of every token in the MASP
/// token map to zero
fn zero_reward_params<S, TransToken>(storage: &mut S) -> Result<()>
where
    S: StorageWrite + StorageRead,
    TransToken: trans_token::Keys,
{
    let token_map: TokenMap =
        storage.read(&masp_token_map_key())?.unwrap_or_default();
    for token in token_map.values() {
        storage.write(
            &masp_max_reward_rate_key::<TransToken>(token),
            Dec::zero(),
        )?;
        storage.write(
            &masp_last_inflation_key::<TransToken>(token),
            Amount::zero(),
        )?;
        tracing::info!("MASP rewards reset: zeroed reward rate of {token}");
    }
    Ok(())
}

/// Strip the rewards published at MASP epoch `reset_from` or later out of
/// every conversion leaf.
///
/// The conversion published at MASP epoch `k` takes a token from epoch
/// `k - 1` to `k` and pays its reward in the native reward assets. Each leaf
/// holds the sum of the conversions from its own epoch up to the latest one:
/// `-p TOKEN@own + p TOKEN@latest + rewards(own + 1 ..= latest)`. Only the
/// reward terms are changed, so every leaf keeps converting to the latest
/// epoch and later conversion updates keep working. With
/// `cut = reset_from - 1`:
/// - a leaf of an epoch before `cut` loses the rewards held by its token's leaf
///   at `cut`, which are exactly the ones published from `reset_from`;
/// - a leaf of epoch `cut` or later loses all its rewards;
/// - a leaf whose token has no leaf at `cut` (it stopped being rewarded before
///   it) is left as is.
///
/// With `reset_from` at zero every leaf loses all its rewards.
///
/// The native token's own reward is not a separate term but the growth of
/// its precision, which cannot be stripped. This fails if the native
/// precision changed from `cut` on. Leaf positions and the tree are left stale.
pub fn strip_rewards(
    state: &mut ConversionState,
    native_token: &Address,
    reset_from: MaspEpoch,
) -> Result<StripStats> {
    let cut_epoch = reset_from.prev();
    let from_cut = |epoch: MaspEpoch| cut_epoch.is_none_or(|cut| epoch >= cut);
    let reward_assets =
        encode_reward_asset_types(native_token).into_storage_result()?;

    check_native_precision_unchanged(state, native_token, from_cut)?;

    // The rewards published from `reset_from` on, per token: the ones held
    // by its leaf at the cut epoch
    let mut rewards_from_reset =
        BTreeMap::<(Address, Denomination, MaspDigitPos), I128Sum>::new();
    for leaf in state.assets.values() {
        if Some(leaf.epoch) == cut_epoch && leaf.token != *native_token {
            rewards_from_reset.insert(
                (leaf.token.clone(), leaf.denom, leaf.digit_pos),
                reward_terms(&leaf.conversion.clone().into(), &reward_assets)?,
            );
        }
    }

    let mut stats = StripStats::default();
    for leaf in state.assets.values_mut() {
        let conversion = I128Sum::from(leaf.conversion.clone());
        let to_strip = if leaf.token == *native_token {
            None
        } else if from_cut(leaf.epoch) {
            Some(reward_terms(&conversion, &reward_assets)?)
        } else {
            rewards_from_reset
                .get(&(leaf.token.clone(), leaf.denom, leaf.digit_pos))
                .cloned()
        };
        match to_strip {
            Some(rewards) if rewards != I128Sum::zero() => {
                leaf.conversion = conversion
                    .checked_sub(&rewards)
                    .ok_or_err_msg("MASP rewards strip underflow")?
                    .into();
                stats.stripped = checked!(stats.stripped + 1)?;
            }
            _ => stats.unchanged = checked!(stats.unchanged + 1)?,
        }
    }
    Ok(stats)
}

/// The terms of a conversion paid in the reward assets
fn reward_terms(
    conversion: &I128Sum,
    reward_assets: &[AssetType],
) -> Result<I128Sum> {
    let mut rewards = I128Sum::zero();
    for asset in reward_assets {
        rewards = rewards
            .checked_add(&I128Sum::from_pair(*asset, conversion.get(asset)))
            .ok_or_err_msg("MASP reward terms overflow")?;
    }
    Ok(rewards)
}

/// Check that the native token's leaves selected by `from_cut` convert one
/// to one, i.e. that the native precision did not grow from the cut epoch
/// on. A native leaf is `-P_own NATIVE@own + P_latest NATIVE@latest`, so its
/// terms must add up to zero.
fn check_native_precision_unchanged(
    state: &ConversionState,
    native_token: &Address,
    from_cut: impl Fn(MaspEpoch) -> bool,
) -> Result<()> {
    for leaf in state.assets.values() {
        if leaf.token != *native_token || !from_cut(leaf.epoch) {
            continue;
        }
        let mut sum = 0i128;
        for (_asset, value) in
            I128Sum::from(leaf.conversion.clone()).components()
        {
            sum = checked!(sum + *value)?;
        }
        if sum != 0 {
            return Err(Error::new_alloc(format!(
                "Cannot strip the MASP rewards: the native token precision \
                 changed at or after MASP epoch {}",
                leaf.epoch
            )));
        }
    }
    Ok(())
}

/// Rebuild the conversion tree from the current leaves, putting every leaf
/// at its position in the assets map
pub fn rebuild_conversion_tree(state: &mut ConversionState) {
    let nodes: Vec<Node> = state
        .assets
        .values_mut()
        .enumerate()
        .map(|(idx, leaf)| {
            leaf.leaf_pos = idx;
            Node::new(leaf.conversion.cmu().to_repr())
        })
        .collect();
    state.tree = FrozenCommitmentTree::new(&nodes);
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod tests {
    use namada_core::address;
    use namada_core::chain::Epoch;
    use namada_state::ReadConversionState;
    use namada_state::testing::TestStorage;

    use super::*;
    use crate::conversion::test_utils::*;

    type TransToken = namada_trans_token::Store<()>;

    fn masp_epoch(epoch: u64) -> MaspEpoch {
        MaspEpoch::try_from_epoch(Epoch(epoch), 1).unwrap()
    }

    /// Storage with all the test tokens rewarded
    fn reward_storage() -> TestStorage {
        let tokens: Vec<_> = tokens()
            .into_iter()
            .map(|(addr, (alias, denom))| (addr, alias, denom))
            .collect();
        init_reward_storage(
            &tokens,
            Amount::from_u64(1_000_000_000_000),
            Amount::from_u64(1_000_000_000),
        )
    }

    /// Like [`reward_storage`], but the native token earns no rewards (as on
    /// mainnet), with conversions published up to MASP epoch `epochs`
    fn storage_with_conversions(epochs: u64) -> TestStorage {
        let mut s = reward_storage();
        s.write(
            &masp_max_reward_rate_key::<TransToken>(&address::testing::nam()),
            Dec::zero(),
        )
        .unwrap();
        for _ in 0..epochs {
            next_masp_epoch(&mut s);
        }
        s
    }

    fn conversions(s: &TestStorage) -> BTreeMap<AssetType, I128Sum> {
        s.conversion_state()
            .assets
            .iter()
            .map(|(asset, leaf)| (*asset, leaf.conversion.clone().into()))
            .collect()
    }

    fn rewards(conversion: &I128Sum) -> I128Sum {
        let reward_assets =
            encode_reward_asset_types(&address::testing::nam()).unwrap();
        reward_terms(conversion, &reward_assets).unwrap()
    }

    fn latest_masp_epoch(s: &TestStorage) -> MaspEpoch {
        s.conversion_state()
            .assets
            .values()
            .map(|leaf| leaf.epoch)
            .max()
            .unwrap()
    }

    /// Resetting from a MASP epoch keeps the rewards published before it,
    /// strips the ones published from it on and leaves the token terms alone.
    #[test]
    fn test_reset_strips_rewards_from_epoch() {
        let nam = address::testing::nam();
        // Publish the conversions of MASP epochs 1 to 3 and snapshot them
        let mut s = storage_with_conversions(3);
        let at_cut = conversions(&s);
        // Publish the conversions of MASP epochs 4 to 6
        for _ in 0..3 {
            next_masp_epoch(&mut s);
        }
        let before = conversions(&s);

        // Strip everything published from MASP epoch 4 (inclusive) on
        reset_masp_rewards_and_conversions::<_, TransToken>(
            &mut s,
            masp_epoch(4),
        )
        .unwrap();

        let cut_epoch = masp_epoch(3);
        let mut num_kept = 0;
        for (asset, leaf) in &s.conversion_state().assets {
            let conv = I128Sum::from(leaf.conversion.clone());
            if leaf.token == nam {
                assert_eq!(conv, before[asset], "native leaf changed");
                continue;
            }
            // The token terms are untouched
            assert_eq!(
                conv.clone() - rewards(&conv),
                before[asset].clone() - rewards(&before[asset]),
                "token terms of leaf {asset} changed"
            );
            if leaf.epoch < cut_epoch {
                // Rewards published up to MASP epoch 3 are kept
                assert_eq!(rewards(&conv), rewards(&at_cut[asset]));
                if rewards(&conv) != I128Sum::zero() {
                    num_kept += 1;
                }
            } else {
                assert_eq!(rewards(&conv), I128Sum::zero());
            }
        }
        assert!(num_kept > 0, "expected some rewards to be kept");
        assert_conversion_state_committed(&s);
    }

    /// After the reset, later conversion updates keep every leaf converting
    /// from its own asset alone to the latest epoch, with the same rewards,
    /// and mint nothing.
    #[test]
    fn test_conversions_keep_working_after_reset() {
        let nam = address::testing::nam();
        let mut s = storage_with_conversions(6);
        reset_masp_rewards_and_conversions::<_, TransToken>(
            &mut s,
            masp_epoch(4),
        )
        .unwrap();
        let after_reset = conversions(&s);
        let minted = native_minted(&s);

        for _ in 0..2 {
            next_masp_epoch(&mut s);
        }

        assert_eq!(native_minted(&s), minted);
        let latest = latest_masp_epoch(&s);
        let assets = &s.conversion_state().assets;
        for (asset, leaf) in assets {
            if leaf.epoch == latest {
                continue;
            }
            let conv = I128Sum::from(leaf.conversion.clone());
            let inputs: Vec<_> = conv
                .components()
                .filter(|(_, value)| **value < 0)
                .map(|(asset, _)| *asset)
                .collect();
            assert_eq!(inputs, vec![*asset], "leaf needs other inputs");
            if leaf.token == nam {
                continue;
            }
            // The only other token term is the token at the latest epoch
            let token_terms = conv.clone() - rewards(&conv);
            for (output, _) in
                token_terms.components().filter(|(_, value)| **value > 0)
            {
                assert_eq!(assets[output].epoch, latest);
                assert_eq!(assets[output].token, leaf.token);
            }
            if let Some(prev) = after_reset.get(asset) {
                assert_eq!(rewards(&conv), rewards(prev));
            }
        }
    }

    /// Resetting from MASP epoch zero strips every reward, zeroes the reward
    /// parameters and stops any further minting.
    #[test]
    fn test_reset_from_zero_strips_everything() {
        let mut s = storage_with_conversions(0);
        let minted_at_start = native_minted(&s);
        for _ in 0..3 {
            next_masp_epoch(&mut s);
        }
        assert!(
            native_minted(&s) > minted_at_start,
            "expected rewards to be minted before the reset"
        );

        reset_masp_rewards_and_conversions::<_, TransToken>(
            &mut s,
            MaspEpoch::zero(),
        )
        .unwrap();

        for token in tokens().keys() {
            let rate: Dec = s
                .read(&masp_max_reward_rate_key::<TransToken>(token))
                .unwrap()
                .unwrap();
            assert_eq!(rate, Dec::zero());
            let last_inflation: Amount = s
                .read(&masp_last_inflation_key::<TransToken>(token))
                .unwrap()
                .unwrap();
            assert_eq!(last_inflation, Amount::zero());
        }
        let state = s.conversion_state();
        assert_eq!(state.tree.size(), state.assets.len());
        for (idx, leaf) in state.assets.values().enumerate() {
            if leaf.token != address::testing::nam() {
                assert_eq!(
                    rewards(&leaf.conversion.clone().into()),
                    I128Sum::zero()
                );
            }
            assert_eq!(leaf.leaf_pos, idx);
        }
        assert_conversion_state_committed(&s);

        // No more NAM gets minted for rewards after the reset
        let before = native_minted(&s);
        for _ in 0..3 {
            next_masp_epoch(&mut s);
        }
        assert_eq!(native_minted(&s), before);
    }

    /// The reset refuses to run if the native token precision grew from the
    /// cut epoch on, since that reward cannot be stripped.
    #[test]
    fn test_reset_fails_if_native_precision_changed() {
        let nam = address::testing::nam();
        let mut s = storage_with_conversions(6);
        // Make a native leaf after the cut epoch pay out more than it takes
        // in, as it does when the native precision grows
        let (asset, leaf) = s
            .conversion_state_mut()
            .assets
            .iter_mut()
            .find(|(_, leaf)| leaf.token == nam && leaf.epoch == masp_epoch(4))
            .unwrap();
        leaf.conversion = (I128Sum::from(leaf.conversion.clone())
            + I128Sum::from_pair(*asset, 1))
        .into();
        let before = conversions(&s);

        let result =
            strip_rewards(s.conversion_state_mut(), &nam, masp_epoch(4));

        assert!(result.is_err());
        assert_eq!(conversions(&s), before, "leaves changed on failure");
    }

    /// Leaves of a token without a leaf at the cut epoch are left untouched.
    #[test]
    fn test_strip_keeps_tokens_without_cut_leaf() {
        let mut s = storage_with_conversions(3);
        let snapshot = conversions(&s);
        let btc = address::testing::btc();
        // Remove BTC's leaves from the cut epoch on, as if it had stopped
        // being rewarded before it
        let cut_epoch = masp_epoch(2);
        s.conversion_state_mut()
            .assets
            .retain(|_, leaf| leaf.token != btc || leaf.epoch < cut_epoch);

        strip_rewards(
            s.conversion_state_mut(),
            &address::testing::nam(),
            masp_epoch(3),
        )
        .unwrap();

        let mut num_btc = 0;
        for (asset, leaf) in &s.conversion_state().assets {
            if leaf.token == btc {
                assert_eq!(
                    I128Sum::from(leaf.conversion.clone()),
                    snapshot[asset]
                );
                num_btc += 1;
            }
        }
        assert!(num_btc > 0);
    }
}
