//! Bridge pool roots validation.

use namada_core::chain::BlockHeight;
use namada_core::keccak::keccak_hash;
use namada_proof_of_stake::queries::{
    get_validator_eth_hot_key, get_validator_protocol_key,
};
use namada_state::{DBIter, DBRead, StorageHasher, StorageRead, WlState};
use namada_systems::governance;
use namada_tx::{SignableEthMessage, Signed};
use namada_vote_ext::bridge_pool_roots;

use super::VoteExtensionError;
use crate::storage::eth_bridge_queries::EthBridgeQueries;

/// Validates a vote extension issued at the provided
/// block height signing over the latest Ethereum bridge
/// pool root and nonce.
///
/// Checks that at epoch of the provided height:
///  * The inner Namada address corresponds to a consensus validator.
///  * Check that the root and nonce are correct.
///  * The validator correctly signed the extension.
///  * The validator signed over the correct height inside of the extension.
///  * Check that the inner signature is valid.
pub fn validate_bp_roots_vext<'db, D, H, Gov>(
    state: &WlState<'db, D, H>,
    ext: &Signed<bridge_pool_roots::Vext>,
    last_height: BlockHeight,
) -> Result<(), VoteExtensionError>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    // NOTE: for ABCI++, we should pass
    // `last_height` here, instead of `ext.data.block_height`
    let ext_height_epoch =
        match state.get_epoch_at_height(ext.data.block_height).unwrap() {
            Some(epoch) => epoch,
            _ => {
                tracing::debug!(
                    block_height = ?ext.data.block_height,
                    "The epoch of the Bridge pool root's vote extension's \
                     block height should always be known",
                );
                return Err(VoteExtensionError::UnexpectedEpoch);
            }
        };
    if !state
        .ethbridge_queries()
        .is_bridge_active_at(ext_height_epoch)
    {
        tracing::debug!(
            vext_epoch = ?ext_height_epoch,
            "The Ethereum bridge was not enabled when the pool
             root's vote extension was cast",
        );
        return Err(VoteExtensionError::EthereumBridgeInactive);
    }

    if ext.data.block_height > last_height {
        tracing::debug!(
            ext_height = ?ext.data.block_height,
            ?last_height,
            "Bridge pool root's vote extension issued for a block height \
             higher than the chain's last height."
        );
        return Err(VoteExtensionError::UnexpectedBlockHeight);
    }
    if ext.data.block_height.0 == 0 {
        tracing::debug!("Dropping vote extension issued at genesis");
        return Err(VoteExtensionError::UnexpectedBlockHeight);
    }

    // get the public key associated with this validator
    let validator = &ext.data.validator_addr;
    let pk = get_validator_protocol_key::<_, Gov>(
        state,
        validator,
        ext_height_epoch,
    )
    .ok()
    .flatten()
    .ok_or_else(|| {
        tracing::debug!(
            %validator,
            "Could not get public key from Storage for some validator, \
             while validating Bridge pool root's vote extension"
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
            "Failed to verify the signature of an Bridge pool root's vote \
             extension issued by some validator"
        );
        VoteExtensionError::VerifySigFailed
    })?;

    let bp_root = state
        .ethbridge_queries()
        .get_bridge_pool_root_at_height(ext.data.block_height)
        .expect("We asserted that the queried height is correct")
        .0;
    let nonce = state
        .ethbridge_queries()
        .get_bridge_pool_nonce_at_height(ext.data.block_height)
        .to_bytes();
    let signed = Signed::<_, SignableEthMessage>::new_from(
        keccak_hash([bp_root, nonce].concat()),
        ext.data.sig.clone(),
    );
    let pk =
        get_validator_eth_hot_key::<_, Gov>(state, validator, ext_height_epoch)
            .ok()
            .flatten()
            .expect("A validator should have an Ethereum hot key in storage.");
    signed.verify(&pk).map_err(|err| {
        tracing::debug!(
            ?err,
            ?signed.sig,
            ?pk,
            %validator,
            "Failed to verify the signature of an Bridge pool root \
            issued by some validator."
        );
        VoteExtensionError::InvalidBPRootSig
    })?;
    Ok(())
}
