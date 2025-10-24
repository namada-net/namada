//! Functions dealing with bridge pool root hash.

use eyre::Result;
use namada_core::address::Address;
use namada_core::chain::BlockHeight;
use namada_core::collections::{HashMap, HashSet};
use namada_core::keccak::keccak_hash;
use namada_core::key::{SignableEthMessage, common};
use namada_core::token::Amount;
use namada_state::{DB, DBIter, StorageHasher, WlState};
use namada_storage::{StorageRead, StorageWrite};
use namada_systems::governance;
use namada_tx::Signed;
use namada_tx::data::BatchedTxResult;
use namada_vote_ext::bridge_pool_roots::{self, MultiSignedVext, SignedVext};

use crate::protocol::transactions::utils::GetVoters;
use crate::protocol::transactions::votes::update::NewVotes;
use crate::protocol::transactions::votes::{Votes, calculate_new};
use crate::protocol::transactions::{ChangedKeys, utils, votes};
use crate::storage::bridge_pool::get_signed_root_key;
use crate::storage::eth_bridge_queries::EthBridgeQueries;
use crate::storage::proof::BridgePoolRootProof;
use crate::storage::vote_tallies::{self, BridgePoolRoot};

/// Sign the latest Bridge pool root, and return the associated
/// vote extension protocol transaction.
pub fn sign_bridge_pool_root<D, H>(
    state: &WlState<D, H>,
    validator_addr: &Address,
    eth_hot_key: &common::SecretKey,
    protocol_key: &common::SecretKey,
) -> Option<bridge_pool_roots::SignedVext>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if !state.ethbridge_queries().is_bridge_active() {
        return None;
    }
    let bp_root = state.ethbridge_queries().get_bridge_pool_root().0;
    let nonce = state.ethbridge_queries().get_bridge_pool_nonce().to_bytes();
    let to_sign = keccak_hash([bp_root.as_slice(), nonce.as_slice()].concat());
    let signed = Signed::<_, SignableEthMessage>::new(eth_hot_key, to_sign);
    let ext = bridge_pool_roots::Vext {
        block_height: state.in_mem().get_last_block_height(),
        validator_addr: validator_addr.clone(),
        sig: signed.sig,
    };
    Some(ext.sign(protocol_key))
}

/// Applies a tally of signatures on over the Ethereum
/// bridge pool root and nonce. Note that every signature
/// passed into this function will be for the same
/// root and nonce.
///
/// For roots + nonces which have been seen by a quorum of
/// validators, the signature is made available for bridge
/// pool proofs.
pub fn apply_derived_tx<D, H, Gov>(
    state: &mut WlState<D, H>,
    vext: MultiSignedVext,
) -> Result<BatchedTxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<D, H>>,
{
    if vext.is_empty() {
        return Ok(BatchedTxResult::default());
    }
    tracing::info!(
        bp_root_sigs = vext.len(),
        "Applying state updates derived from signatures of the Ethereum \
         bridge pool root and nonce."
    );
    let voting_powers = utils::get_voting_powers(state, &vext)?;
    let root_height = vext.iter().next().unwrap().data.block_height;
    let (partial_proof, seen_by) = parse_vexts::<D, H, Gov>(state, vext);

    // return immediately if a complete proof has already been acquired
    let bp_key = vote_tallies::Keys::from((&partial_proof, root_height));
    let seen =
        votes::storage::maybe_read_seen(state, &bp_key)?.unwrap_or(false);
    if seen {
        tracing::debug!(
            ?root_height,
            ?partial_proof,
            "Bridge pool root tally is already complete"
        );
        return Ok(BatchedTxResult::default());
    }

    // apply updates to the bridge pool root.
    let (mut changed, confirmed_update) = apply_update::<D, H, Gov>(
        state,
        bp_key,
        partial_proof,
        seen_by,
        &voting_powers,
    )?;

    // if the root is confirmed, update storage and add
    // relevant key to changed.
    if let Some(proof) = confirmed_update {
        let signed_root_key = get_signed_root_key();
        let should_write_root = state
            .read::<(BridgePoolRoot, BlockHeight)>(&signed_root_key)
            .expect(
                "Reading a signed Bridge pool root from storage should not \
                 fail",
            )
            .map(|(_, existing_root_height)| {
                // only write the newly confirmed signed root if
                // it is more recent than the existing root in
                // storage
                existing_root_height < root_height
            })
            .unwrap_or({
                // if no signed root was present in storage, write the new one
                true
            });
        if should_write_root {
            tracing::debug!(
                ?root_height,
                "New Bridge pool root proof acquired"
            );
            state.write(&signed_root_key, (proof, root_height)).expect(
                "Writing a signed Bridge pool root to storage should not fail.",
            );
            changed.insert(get_signed_root_key());
        } else {
            tracing::debug!(
                ?root_height,
                "Discarding outdated Bridge pool root proof"
            );
        }
    }

    Ok(BatchedTxResult {
        changed_keys: changed,
        ..Default::default()
    })
}

impl GetVoters for &MultiSignedVext {
    fn get_voters(self) -> HashSet<(Address, BlockHeight)> {
        self.iter()
            .map(|signed| {
                (signed.data.validator_addr.clone(), signed.data.block_height)
            })
            .collect()
    }
}

/// Convert a set of signatures over bridge pool roots and nonces (at a certain
/// height) into a partial proof and a new set of votes.
fn parse_vexts<D, H, Gov>(
    state: &WlState<D, H>,
    multisigned: MultiSignedVext,
) -> (BridgePoolRoot, Votes)
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<D, H>>,
{
    let height = multisigned.iter().next().unwrap().data.block_height;
    let epoch = state.get_epoch_at_height(height).unwrap();
    let root = state
        .ethbridge_queries()
        .get_bridge_pool_root_at_height(height)
        .expect("A BP root should be available at the given height");
    let nonce = state
        .ethbridge_queries()
        .get_bridge_pool_nonce_at_height(height);
    let mut partial_proof = BridgePoolRootProof::new((root, nonce));
    partial_proof.attach_signature_batch(multisigned.clone().into_iter().map(
        |SignedVext(signed)| {
            (
                state
                    .ethbridge_queries()
                    .get_eth_addr_book::<Gov>(
                        &signed.data.validator_addr,
                        epoch,
                    )
                    .unwrap(),
                signed.data.sig,
            )
        },
    ));

    let seen_by: Votes = multisigned
        .0
        .into_iter()
        .map(|SignedVext(signed)| {
            (signed.data.validator_addr, signed.data.block_height)
        })
        .collect();
    (BridgePoolRoot(partial_proof), seen_by)
}

/// This vote updates the voting power backing a bridge pool root / nonce in
/// storage. If a quorum backs the root / nonce, a boolean is returned
/// indicating that it has been confirmed.
///
/// In all instances, the changed storage keys are returned.
fn apply_update<D, H, Gov>(
    state: &mut WlState<D, H>,
    bp_key: vote_tallies::Keys<BridgePoolRoot>,
    mut update: BridgePoolRoot,
    seen_by: Votes,
    voting_powers: &HashMap<(Address, BlockHeight), Amount>,
) -> Result<(ChangedKeys, Option<BridgePoolRoot>)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<D, H>>,
{
    let partial_proof = votes::storage::read_body(state, &bp_key);
    let (vote_tracking, changed, confirmed, already_present) = if let Ok(
        partial,
    ) =
        partial_proof
    {
        tracing::debug!(
            %bp_key.prefix,
            "Signatures for this Bridge pool update already exists in storage",
        );
        update.0.attach_signature_batch(partial.0.signatures);
        let new_votes = NewVotes::new(seen_by, voting_powers)?;
        let (vote_tracking, changed) = votes::update::calculate::<D, H, Gov, _>(
            state, &bp_key, new_votes,
        )?;
        if changed.is_empty() {
            return Ok((changed, None));
        }
        let confirmed = vote_tracking.seen && changed.contains(&bp_key.seen());
        (vote_tracking, changed, confirmed, true)
    } else {
        tracing::debug!(%bp_key.prefix, "No validator has signed this bridge pool update before.");
        let vote_tracking =
            calculate_new::<D, H, Gov>(state, seen_by, voting_powers)?;
        let changed = bp_key.into_iter().collect();
        let confirmed = vote_tracking.seen;
        (vote_tracking, changed, confirmed, false)
    };

    votes::storage::write(
        state,
        &bp_key,
        &update,
        &vote_tracking,
        already_present,
    )?;
    Ok((changed, confirmed.then_some(update)))
}

#[cfg(test)]
mod test_apply_bp_roots_to_storage {

    use std::collections::BTreeSet;

    use assert_matches::assert_matches;
    use namada_core::address;
    use namada_core::ethereum_events::Uint;
    use namada_core::keccak::KeccakHash;
    use namada_core::storage::Key;
    use namada_core::voting_power::FractionalVotingPower;
    use namada_proof_of_stake::parameters::OwnedPosParams;
    use namada_proof_of_stake::queries::get_total_voting_power;
    use namada_proof_of_stake::storage::{
        read_consensus_validator_set_addresses_with_stake, write_pos_params,
    };
    use namada_state::testing::TestState;

    use super::*;
    use crate::protocol::transactions::votes::{
        EpochedVotingPower, EpochedVotingPowerExt,
    };
    use crate::storage::bridge_pool::{get_key_from_hash, get_nonce_key};
    use crate::storage::vp;
    use crate::test_utils::{self, GovStore};

    /// The data needed to run a test.
    struct TestPackage {
        /// Two validators
        validators: [Address; 3],
        /// The validator keys.
        keys: HashMap<Address, test_utils::TestValidatorKeys>,
        /// Storage.
        state: TestState,
    }

    /// Setup storage for tests.
    ///
    ///  * Creates three validators with equal voting power.
    ///  * Makes sure that a bridge pool nonce and root key are initialized.
    ///  * Commits a bridge pool merkle tree at height 100.
    fn setup() -> TestPackage {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let validator_c = address::testing::established_address_4();
        let (mut state, keys) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), Amount::native_whole(100)),
                (validator_b.clone(), Amount::native_whole(100)),
                (validator_c.clone(), Amount::native_whole(40)),
            ]),
        );
        // First commit
        state.in_mem_mut().block.height = 1.into();
        state.commit_block().unwrap();

        vp::bridge_pool::init_storage(&mut state);
        test_utils::commit_bridge_pool_root_at_height(
            &mut state,
            &KeccakHash([1; 32]),
            99.into(),
        );
        test_utils::commit_bridge_pool_root_at_height(
            &mut state,
            &KeccakHash([1; 32]),
            100.into(),
        );
        state
            .write(&get_key_from_hash(&KeccakHash([1; 32])), BlockHeight(101))
            .expect("Test failed");
        state
            .write(&get_nonce_key(), Uint::from(42))
            .expect("Test failed");
        state.commit_block().unwrap();
        TestPackage {
            validators: [validator_a, validator_b, validator_c],
            keys,
            state,
        }
    }

    #[ignore]
    #[test]
    /// Test that applying a tx changes the expected keys
    /// if a quorum is not present.
    ///
    /// There are two code paths to test: If the key existed in
    /// storage previously or not.
    fn test_update_changed_keys_not_quorum() {
        let TestPackage {
            validators,
            keys,
            mut state,
        } = setup();
        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        let BatchedTxResult { changed_keys, .. } =
            apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
                .expect("Test failed");
        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
        ));
        let expected: BTreeSet<Key> = bp_root_key.into_iter().collect();
        assert_eq!(expected, changed_keys);

        let hot_key = &keys[&validators[2]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[2].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[2]].protocol);

        let BatchedTxResult { changed_keys, .. } =
            apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
                .expect("Test failed");

        let expected: BTreeSet<Key> =
            [bp_root_key.seen_by(), bp_root_key.voting_power()]
                .into_iter()
                .collect();
        assert_eq!(expected, changed_keys);
    }

    #[ignore]
    #[test]
    /// Test that applying a tx changes the expected keys
    /// if a quorum is present and the tallies were not
    /// present in storage.
    fn test_update_changed_keys_quorum_not_in_storage() {
        let TestPackage {
            validators,
            keys,
            mut state,
        } = setup();
        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;
        let mut vexts: MultiSignedVext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol)
        .into();
        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        vexts.insert(vext);
        let BatchedTxResult { changed_keys, .. } =
            apply_derived_tx::<_, _, GovStore<_>>(&mut state, vexts)
                .expect("Test failed");
        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
        ));

        let mut expected: BTreeSet<Key> = bp_root_key.into_iter().collect();
        expected.insert(get_signed_root_key());
        assert_eq!(expected, changed_keys);
    }

    #[ignore]
    #[test]
    /// Test that applying a tx changes the expected keys
    /// if quorum is present and a partial tally already existed
    /// in storage.
    fn test_update_changed_keys_quorum_in_storage() {
        let TestPackage {
            validators,
            keys,
            mut state,
        } = setup();
        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
            .expect("Test failed");

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        let BatchedTxResult { changed_keys, .. } =
            apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
                .expect("Test failed");
        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
        ));
        let expected: BTreeSet<Key> = [
            bp_root_key.seen(),
            bp_root_key.seen_by(),
            bp_root_key.voting_power(),
            get_signed_root_key(),
        ]
        .into_iter()
        .collect();
        assert_eq!(expected, changed_keys);
    }

    #[ignore]
    #[test]
    /// Test that the voting power key is updated correctly.
    fn test_voting_power() {
        let TestPackage {
            validators,
            keys,
            mut state,
        } = setup();
        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
        ));

        let hot_key = &keys[&validators[0]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
            .expect("Test failed");
        let voting_power = state
            .read::<EpochedVotingPower>(&bp_root_key.voting_power())
            .expect("Test failed")
            .expect("Test failed")
            .fractional_stake::<_, _, GovStore<_>>(&state);
        assert_eq!(
            voting_power,
            FractionalVotingPower::new_u64(5, 12).unwrap()
        );

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        _ = apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
            .expect("Test failed");
        let voting_power = state
            .read::<EpochedVotingPower>(&bp_root_key.voting_power())
            .expect("Test failed")
            .expect("Test failed")
            .fractional_stake::<_, _, GovStore<_>>(&state);
        assert_eq!(voting_power, FractionalVotingPower::new_u64(5, 6).unwrap());
    }

    #[ignore]
    #[test]
    /// Test that the seen storage key is updated correctly.
    fn test_seen() {
        let TestPackage {
            validators,
            keys,
            mut state,
        } = setup();
        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;

        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
        ));

        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
            .expect("Test failed");

        let seen: bool = state
            .read(&bp_root_key.seen())
            .expect("Test failed")
            .expect("Test failed");
        assert!(!seen);

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        _ = apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
            .expect("Test failed");

        let seen: bool = state
            .read(&bp_root_key.seen())
            .expect("Test failed")
            .expect("Test failed");
        assert!(seen);
    }

    #[ignore]
    #[test]
    /// Test that the seen by keys is updated correctly.
    fn test_seen_by() {
        let TestPackage {
            validators,
            keys,
            mut state,
        } = setup();
        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;

        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
        ));

        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
            .expect("Test failed");

        let expected = Votes::from([(validators[0].clone(), 100.into())]);
        let seen_by: Votes = state
            .read(&bp_root_key.seen_by())
            .expect("Test failed")
            .expect("Test failed");
        assert_eq!(seen_by, expected);

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        _ = apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
            .expect("Test failed");

        let expected = Votes::from([
            (validators[0].clone(), 100.into()),
            (validators[1].clone(), 100.into()),
        ]);
        let seen_by: Votes = state
            .read(&bp_root_key.seen_by())
            .expect("Test failed")
            .expect("Test failed");
        assert_eq!(seen_by, expected);
    }

    #[ignore]
    #[test]
    /// Test that the root and nonce are stored correctly.
    fn test_body() {
        let TestPackage {
            validators,
            keys,
            mut state,
        } = setup();
        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;
        let mut expected =
            BridgePoolRoot(BridgePoolRootProof::new((root, nonce)));
        let bp_root_key = vote_tallies::Keys::from((&expected, 100.into()));

        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        };
        expected.0.attach_signature(
            state
                .ethbridge_queries()
                .get_eth_addr_book::<GovStore<_>>(
                    &validators[0],
                    state.get_epoch_at_height(100.into()).unwrap(),
                )
                .expect("Test failed"),
            vext.sig.clone(),
        );
        let vext = vext.sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
            .expect("Test failed");

        let proof: BridgePoolRootProof = state
            .read(&bp_root_key.body())
            .expect("Test failed")
            .expect("Test failed");
        assert_eq!(proof.data, expected.0.data);
        assert_eq!(proof.signatures, expected.0.signatures);
    }

    #[ignore]
    #[test]
    /// Test that we update the bridge pool storage once a quorum
    /// backs the new nonce and root.
    fn test_quorum() {
        let TestPackage {
            validators,
            keys,
            mut state,
        } = setup();
        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());

        assert!(
            state
                .read::<(BridgePoolRoot, BlockHeight)>(&get_signed_root_key())
                .expect("Test failed")
                .is_none()
        );

        let hot_key = &keys[&validators[0]].eth_bridge;
        let mut vexts: MultiSignedVext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol)
        .into();

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);

        vexts.insert(vext);
        let epoch = state.get_epoch_at_height(100.into()).unwrap();
        let sigs: Vec<_> = vexts
            .iter()
            .map(|s| {
                (
                    state
                        .ethbridge_queries()
                        .get_eth_addr_book::<GovStore<_>>(
                            &s.data.validator_addr,
                            epoch,
                        )
                        .expect("Test failed"),
                    s.data.sig.clone(),
                )
            })
            .collect();

        _ = apply_derived_tx::<_, _, GovStore<_>>(&mut state, vexts)
            .expect("Test failed");
        let (proof, _): (BridgePoolRootProof, BlockHeight) = state
            .read(&get_signed_root_key())
            .expect("Test failed")
            .expect("Test failed");
        let mut expected = BridgePoolRootProof::new((root, nonce));
        expected.attach_signature_batch(sigs);
        assert_eq!(proof.signatures, expected.signatures);
        assert_eq!(proof.data, expected.data);
    }

    /// Test that when we acquire a complete BP roots proof,
    /// the block height stored in storage is that of the
    /// tree root that was decided.
    #[test]
    fn test_bp_roots_across_epoch_boundaries() {
        // the validators that will vote in the tally
        let validator_1 = address::testing::established_address_1();
        let validator_1_stake = Amount::native_whole(100);

        let validator_2 = address::testing::established_address_2();
        let validator_2_stake = Amount::native_whole(100);

        let validator_3 = address::testing::established_address_3();
        let validator_3_stake = Amount::native_whole(100);

        // start epoch 0 with validator 1
        let (mut state, keys) = test_utils::setup_storage_with_validators(
            HashMap::from([(validator_1.clone(), validator_1_stake)]),
        );

        // update the pos params
        let params = OwnedPosParams {
            pipeline_len: 1,
            ..Default::default()
        };
        write_pos_params(&mut state, &params).expect("Test failed");

        // insert validators 2 and 3 at epoch 1
        test_utils::append_validators_to_storage(
            &mut state,
            HashMap::from([
                (validator_2.clone(), validator_2_stake),
                (validator_3.clone(), validator_3_stake),
            ]),
        );

        // query validators to make sure they were inserted correctly
        macro_rules! query_validators {
            () => {
                |epoch: u64| {
                    read_consensus_validator_set_addresses_with_stake(
                        &state,
                        epoch.into(),
                    )
                    .unwrap()
                    .into_iter()
                    .map(|validator| {
                        (validator.address, validator.bonded_stake)
                    })
                    .collect::<HashMap<_, _>>()
                }
            };
        }
        let query_validators = query_validators!();
        let epoch_0_validators = query_validators(0);
        let epoch_1_validators = query_validators(1);
        _ = query_validators;
        assert_eq!(
            epoch_0_validators,
            HashMap::from([(validator_1.clone(), validator_1_stake)])
        );
        assert_eq!(
            get_total_voting_power::<_, GovStore<_>>(&state, 0.into()),
            validator_1_stake,
        );
        assert_eq!(
            epoch_1_validators,
            HashMap::from([
                (validator_1.clone(), validator_1_stake),
                (validator_2, validator_2_stake),
                (validator_3, validator_3_stake),
            ])
        );
        assert_eq!(
            get_total_voting_power::<_, GovStore<_>>(&state, 1.into()),
            validator_1_stake + validator_2_stake + validator_3_stake,
        );

        // set up the bridge pool's storage
        vp::bridge_pool::init_storage(&mut state);
        test_utils::commit_bridge_pool_root_at_height(
            &mut state,
            &KeccakHash([1; 32]),
            3.into(),
        );

        // construct proof
        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validator_1].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validator_1.clone(),
            block_height: 3.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validator_1].protocol);

        _ = apply_derived_tx::<_, _, GovStore<_>>(&mut state, vext.into())
            .expect("Test failed");

        // query validator set of the proof
        // (should be the one from epoch 0)
        let (_, root_height) = state
            .ethbridge_queries()
            .get_signed_bridge_pool_root()
            .expect("Test failed");
        let root_epoch = state
            .get_epoch_at_height(root_height)
            .unwrap()
            .expect("Test failed");

        let query_validators = query_validators!();
        let root_epoch_validators = query_validators(root_epoch.0);
        assert_eq!(epoch_0_validators, root_epoch_validators);
    }

    #[ignore]
    #[test]
    /// Test that a signed root is not overwritten in storage
    /// if a signed root is decided that had been signed at a
    /// less recent block height.
    fn test_more_recent_signed_root_not_overwritten() {
        let TestPackage {
            validators,
            keys,
            mut state,
        } = setup();

        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());

        macro_rules! decide_at_height {
            ($block_height:expr) => {
                let hot_key = &keys[&validators[0]].eth_bridge;
                let vext = bridge_pool_roots::Vext {
                    validator_addr: validators[0].clone(),
                    block_height: $block_height.into(),
                    sig: Signed::<_, SignableEthMessage>::new(
                        hot_key,
                        to_sign.clone(),
                    )
                    .sig,
                }
                .sign(&keys[&validators[0]].protocol);
                _ = apply_derived_tx::<_, _, GovStore<_>>(
                    &mut state,
                    vext.into(),
                )
                .expect("Test failed");
                let hot_key = &keys[&validators[1]].eth_bridge;
                let vext = bridge_pool_roots::Vext {
                    validator_addr: validators[1].clone(),
                    block_height: $block_height.into(),
                    sig: Signed::<_, SignableEthMessage>::new(
                        hot_key,
                        to_sign.clone(),
                    )
                    .sig,
                }
                .sign(&keys[&validators[1]].protocol);
                _ = apply_derived_tx::<_, _, GovStore<_>>(
                    &mut state,
                    vext.into(),
                )
                .expect("Test failed");
            };
        }

        // decide bridge pool root signed at block height 100
        decide_at_height!(100);

        // check the signed root in storage
        let root_in_storage = state
            .read::<(BridgePoolRoot, BlockHeight)>(&get_signed_root_key())
            .expect("Test failed - storage read failed")
            .expect("Test failed - no signed root in storage");
        assert_matches!(
            root_in_storage,
            (BridgePoolRoot(r), BlockHeight(100))
                if r.data.0 == root && r.data.1 == nonce
        );

        // decide bridge pool root signed at block height 99
        decide_at_height!(99);

        // check the signed root in storage is unchanged
        let root_in_storage = state
            .read::<(BridgePoolRoot, BlockHeight)>(&get_signed_root_key())
            .expect("Test failed - storage read failed")
            .expect("Test failed - no signed root in storage");
        assert_matches!(
            root_in_storage,
            (BridgePoolRoot(r), BlockHeight(100))
                if r.data.0 == root && r.data.1 == nonce
        );
    }
}
