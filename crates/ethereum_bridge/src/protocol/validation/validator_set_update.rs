//! Validator set update validation.

use namada_core::chain::Epoch;
use namada_proof_of_stake::queries::get_validator_eth_hot_key;
use namada_state::{DBIter, DBRead, StorageHasher, WlState};
use namada_systems::governance;
use namada_vote_ext::validator_set_update;

use super::VoteExtensionError;
use crate::storage::eth_bridge_queries::{
    EthBridgeQueries, is_bridge_comptime_enabled,
};

/// Validates a validator set update vote extension issued at the
/// epoch provided as an argument.
///
/// # Validation checks
///
/// To validate a [`validator_set_update::SignedVext`], Namada nodes
/// check if:
///
///  * The signing validator is a consensus validator during the epoch
///    `signing_epoch` inside the extension.
///  * A validator set update proof is not available yet for `signing_epoch`.
///  * The validator correctly signed the extension, with its Ethereum hot key.
///  * The validator signed over the epoch inside of the extension, whose value
///    should not be greater than `last_epoch`.
///  * The voting powers in the vote extension correspond to the voting powers
///    of the validators of `signing_epoch + 1`.
///  * The voting powers signed over were Ethereum ABI encoded, normalized to
///    `2^32`, and sorted in descending order.
pub fn validate_valset_upd_vext<'db, D, H, Gov>(
    state: &WlState<'db, D, H>,
    ext: &validator_set_update::SignedVext,
    last_epoch: Epoch,
) -> Result<(), VoteExtensionError>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    let signing_epoch = ext.data.signing_epoch;
    if !is_bridge_comptime_enabled() {
        tracing::debug!(
            vext_epoch = ?signing_epoch,
            "The Ethereum bridge was not enabled when the validator set \
             update's vote extension was cast",
        );
        return Err(VoteExtensionError::EthereumBridgeInactive);
    }
    if state.in_mem().last_block.is_none() {
        tracing::debug!(
            "Dropping validator set update vote extension issued at genesis"
        );
        return Err(VoteExtensionError::UnexpectedBlockHeight);
    }
    if signing_epoch > last_epoch {
        tracing::debug!(
            vext_epoch = ?signing_epoch,
            ?last_epoch,
            "Validator set update vote extension issued for an epoch \
             greater than the last one.",
        );
        return Err(VoteExtensionError::UnexpectedEpoch);
    }
    if state
        .ethbridge_queries()
        .valset_upd_seen(signing_epoch.next())
    {
        let err = VoteExtensionError::ValsetUpdProofAvailable;
        tracing::debug!(
            proof_epoch = ?signing_epoch.next(),
            "{err}"
        );
        return Err(err);
    }
    // verify if the new epoch validators' voting powers in storage match
    // the voting powers in the vote extension
    let mut no_local_consensus_eth_addresses = 0;
    for (eth_addr_book, namada_addr, namada_power) in
        state
            .ethbridge_queries()
            .get_consensus_eth_addresses::<Gov>(signing_epoch.next())
    {
        let &ext_power = match ext.data.voting_powers.get(&eth_addr_book) {
            Some(voting_power) => voting_power,
            _ => {
                tracing::debug!(
                    ?eth_addr_book,
                    "Could not find expected Ethereum addresses in valset upd \
                     vote extension",
                );
                return Err(VoteExtensionError::ValidatorMissingFromExtension);
            }
        };
        if namada_power != ext_power {
            tracing::debug!(
                validator = %namada_addr,
                expected = ?namada_power,
                got = ?ext_power,
                "Found unexpected voting power value in valset upd vote extension",
            );
            return Err(VoteExtensionError::DivergesFromStorage);
        }
        // At most the number of consensus validator addresses - cannot overflow
        #[allow(clippy::arithmetic_side_effects)]
        {
            no_local_consensus_eth_addresses += 1;
        }
    }
    if no_local_consensus_eth_addresses != ext.data.voting_powers.len() {
        tracing::debug!(
            no_ext_consensus_eth_addresses = ext.data.voting_powers.len(),
            no_local_consensus_eth_addresses,
            "Superset of the next validator set was included in the validator \
             set update vote extension",
        );
        return Err(VoteExtensionError::ExtraValidatorsInExtension);
    }
    // get the public key associated with this validator
    let validator = &ext.data.validator_addr;
    let pk = get_validator_eth_hot_key::<_, Gov>(
        state,
        validator,
        signing_epoch,
    )
    .ok()
    .flatten()
    .ok_or_else(|| {
        tracing::debug!(
            %validator,
            "Could not get Ethereum hot key from Storage for some validator, \
             while validating valset upd vote extension"
        );
        VoteExtensionError::PubKeyNotInStorage
    })?;
    // verify the signature of the vote extension
    ext.verify(&pk).map_err(|err| {
        tracing::debug!(
            ?err,
            ?ext.sig,
            ?pk,
            %validator,
            "Failed to verify the signature of a valset upd vote \
             extension issued by some validator"
        );
        VoteExtensionError::VerifySigFailed
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use namada_core::ethereum_events::EthAddress;
    use namada_core::key::{RefTo, common};
    use namada_vote_ext::validator_set_update::{EthAddrBook, VotingPowersMap};

    use super::*;
    use crate::storage::eth_bridge_queries::is_bridge_comptime_enabled;
    use crate::test_utils::{self, GovStore};

    /// Test that we reject vote extensions containing a superset of the
    /// next validator set in storage.
    #[test]
    fn test_superset_valsetupd_rejected() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }

        let (state, keys) = test_utils::setup_default_storage();
        let (validator, validator_stake) = test_utils::default_validator();

        let hot_key_addr = {
            let hot_key = &keys
                .get(&validator)
                .expect("Test failed")
                .eth_bridge
                .ref_to();

            match hot_key {
                common::PublicKey::Secp256k1(ref k) => k.into(),
                _ => panic!("Test failed"),
            }
        };
        let cold_key_addr = {
            let cold_key =
                &keys.get(&validator).expect("Test failed").eth_gov.ref_to();

            match cold_key {
                common::PublicKey::Secp256k1(ref k) => k.into(),
                _ => panic!("Test failed"),
            }
        };

        let voting_powers = {
            let mut map = VotingPowersMap::new();
            map.insert(
                EthAddrBook {
                    hot_key_addr,
                    cold_key_addr,
                },
                validator_stake,
            );
            map.insert(
                EthAddrBook {
                    hot_key_addr: EthAddress([0; 20]),
                    cold_key_addr: EthAddress([0xff; 20]),
                },
                validator_stake,
            );
            map
        };

        let ext = validator_set_update::Vext {
            voting_powers,
            signing_epoch: 0.into(),
            validator_addr: validator.clone(),
        }
        .sign(&keys.get(&validator).expect("Test failed").eth_bridge);

        let result = validate_valset_upd_vext::<_, _, GovStore<_>>(
            &state,
            &ext,
            0.into(),
        );
        assert_matches!(
            result,
            Err(VoteExtensionError::ExtraValidatorsInExtension)
        );
    }
}
