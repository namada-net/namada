//! Implementation of the [`RequestPrepareProposal`] ABCI++ method for the Shell

use std::cell::RefCell;

use namada_sdk::address::Address;
use namada_sdk::gas::TxGasMeter;
use namada_sdk::key::tm_raw_hash_to_string;
use namada_sdk::parameters::get_gas_scale;
use namada_sdk::proof_of_stake::storage::find_validator_by_raw_hash;
use namada_sdk::state::{DB, DBIter, StorageHasher, TempWlState, TxIndex};
use namada_sdk::storage::BlockHeight;
use namada_sdk::token::{Amount, DenominatedAmount};
use namada_sdk::tx::Tx;
use namada_sdk::tx::data::WrapperTx;
use namada_vm::WasmCacheAccess;
use namada_vm::wasm::{TxCache, VpCache};

use super::super::*;
use super::block_alloc::states::{
    BuildingNormalTxBatch, BuildingProtocolTxBatch, NextState, TryAlloc,
    WithNormalTxs, WithoutNormalTxs,
};
use super::block_alloc::{AllocFailure, BlockAllocator, BlockResources};
use crate::config::ValidatorLocalConfig;
use crate::protocol::{self, ShellParams};
use crate::shell::ShellMode;
use crate::shims::abcipp_shim_types::shim::{TxBytes, response};
use crate::tendermint_proto::abci::RequestPrepareProposal;
use crate::tendermint_proto::google::protobuf::Timestamp;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Begin a new block.
    ///
    /// Block construction is documented in `block_alloc`
    /// and `block_alloc::states` (private modules).
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if
    /// the proposal is rejected (unless we can simply overwrite
    /// them in the next block). Furthermore, protocol transactions cannot
    /// affect the ability of a tx to pay its wrapper fees.
    pub fn prepare_proposal(
        &self,
        mut req: RequestPrepareProposal,
    ) -> response::PrepareProposal {
        let txs = if let ShellMode::Validator {
            ref validator_local_config,
            ..
        } = self.mode
        {
            // start counting allotted space for txs
            let alloc = self.get_protocol_txs_allocator();
            // add initial protocol txs
            let (alloc, mut txs) =
                self.build_protocol_tx_with_normal_txs(alloc, &mut req.txs);

            // add wrapper txs
            let tm_raw_hash_string =
                tm_raw_hash_to_string(req.proposer_address);
            let block_proposer =
                find_validator_by_raw_hash(&self.state, tm_raw_hash_string)
                    .unwrap()
                    .expect(
                        "Unable to find native validator address of block \
                         proposer from tendermint raw hash",
                    );
            let (mut normal_txs, alloc) = self.build_normal_txs(
                alloc,
                &req.txs,
                req.time,
                &block_proposer,
                validator_local_config.as_ref(),
            );
            txs.append(&mut normal_txs);
            let mut remaining_txs =
                self.build_protocol_tx_without_normal_txs(alloc, &mut req.txs);
            txs.append(&mut remaining_txs);
            txs
        } else {
            vec![]
        };

        tracing::info!(
            height = req.height,
            num_of_txs = txs.len(),
            "Proposing block"
        );

        response::PrepareProposal { txs }
    }

    /// Get the first state of the block allocator. This is for protocol
    /// transactions.
    #[inline]
    fn get_protocol_txs_allocator(
        &self,
    ) -> BlockAllocator<BuildingProtocolTxBatch<WithNormalTxs>> {
        self.state.read_only().into()
    }

    /// Builds a batch of wrapper  transactions, retrieved from
    /// CometBFT's mempool.
    fn build_normal_txs(
        &self,
        mut alloc: BlockAllocator<BuildingNormalTxBatch>,
        txs: &[TxBytes],
        block_time: Option<Timestamp>,
        block_proposer: &Address,
        proposer_local_config: Option<&ValidatorLocalConfig>,
    ) -> (
        Vec<TxBytes>,
        BlockAllocator<BuildingProtocolTxBatch<WithoutNormalTxs>>,
    ) {
        let block_time = block_time.and_then(|block_time| {
            // If error in conversion, default to last block datetime, it's
            // valid because of mempool check
            TryInto::<DateTimeUtc>::try_into(block_time).ok()
        });
        // This is safe as neither the inner `db` nor `in_mem` are
        // actually mutable, only the `write_log` which is owned by
        // the `TempWlState` struct. The `TempWlState` will be dropped
        // before any other ABCI request is processed.
        let mut temp_state = unsafe { self.state.with_static_temp_write_log() };
        let mut vp_wasm_cache = self.vp_wasm_cache.clone();
        let mut tx_wasm_cache = self.tx_wasm_cache.clone();

        let txs = txs
            .iter()
            .enumerate()
            .filter_map(|(tx_index, tx_bytes)| {
                let result = validate_wrapper_bytes(
                    tx_bytes,
                    TxIndex::must_from_usize(tx_index),
                    self.get_current_decision_height(),
                    block_time,
                    block_proposer,
                    proposer_local_config,
                    &mut temp_state,
                    &mut vp_wasm_cache,
                    &mut tx_wasm_cache
                );
                match result {
                    Ok(gas) => {
                        temp_state.write_log_mut().commit_batch_and_current_tx();
                        Some((tx_bytes.to_owned(), gas))
                    },
                    Err(()) => {
                        temp_state.write_log_mut().drop_batch();
                        None
                    }
                }
            })
            .take_while(|(tx_bytes, tx_gas)| {
                alloc.try_alloc(BlockResources::new(&tx_bytes[..], tx_gas.to_owned()))
                    .map_or_else(
                        |status| match status {
                            AllocFailure::Rejected { bin_resource_left} => {
                                tracing::debug!(
                                    ?tx_bytes,
                                    bin_resource_left,
                                    proposal_height =
                                        ?self.get_current_decision_height(),
                                    "Dropping encrypted tx from the current proposal",
                                );
                                false
                            }
                            AllocFailure::OverflowsBin { bin_resource} => {
                                // TODO(namada#3250): handle tx whose size is greater
                                // than bin size
                                tracing::warn!(
                                    ?tx_bytes,
                                    bin_resource,
                                    proposal_height =
                                        ?self.get_current_decision_height(),
                                    "Dropping large encrypted tx from the current proposal",
                                );
                                true
                            }
                        },
                        |()| true,
                    )
            })
            .map(|(tx, _)| tx)
            .collect();
        let alloc = alloc.next_state();

        (txs, alloc)
    }

    /// Allocate an initial set of protocol txs and advance to the
    /// next allocation state.
    fn build_protocol_tx_with_normal_txs(
        &self,
        alloc: BlockAllocator<BuildingProtocolTxBatch<WithNormalTxs>>,
        txs: &mut Vec<TxBytes>,
    ) -> (BlockAllocator<BuildingNormalTxBatch>, Vec<TxBytes>) {
        let (alloc, txs) = self.build_protocol_txs(alloc, txs);
        (alloc.next_state(), txs)
    }

    /// Allocate protocol txs into any remaining space. After this, no
    /// more allocation will take place.
    fn build_protocol_tx_without_normal_txs(
        &self,
        alloc: BlockAllocator<BuildingProtocolTxBatch<WithoutNormalTxs>>,
        txs: &mut Vec<TxBytes>,
    ) -> Vec<TxBytes> {
        let (_, txs) = self.build_protocol_txs(alloc, txs);
        txs
    }

    /// Builds a batch of protocol transactions.
    fn build_protocol_txs<M>(
        &self,
        mut alloc: BlockAllocator<BuildingProtocolTxBatch<M>>,
        txs: &mut Vec<TxBytes>,
    ) -> (BlockAllocator<BuildingProtocolTxBatch<M>>, Vec<TxBytes>) {
        if self.state.in_mem().last_block.is_none() {
            // genesis should not contain vote extensions.
            //
            // this is because we have not decided any block through
            // consensus yet (hence height 0), which in turn means we
            // have not committed any vote extensions to a block either.
            return (alloc, vec![]);
        }

        let mut deserialized_iter = self.deserialize_vote_extensions(txs);

        let taken = deserialized_iter.by_ref().take_while(|tx_bytes|
            alloc.try_alloc(&tx_bytes[..])
                .map_or_else(
                    |status| match status {
                        AllocFailure::Rejected { bin_resource_left} => {
                            // TODO(namada#3250): maybe we should find a way to include
                            // validator set updates all the time. for instance,
                            // we could have recursive bins -> bin space within
                            // a bin is partitioned into yet more bins. so, we
                            // could have, say, 2/3 of the bin space available
                            // for eth events, and 1/3 available for valset
                            // upds. to be determined, as we implement CheckTx
                            // changes (issue #367)
                            tracing::debug!(
                                ?tx_bytes,
                                bin_resource_left,
                                proposal_height =
                                    ?self.get_current_decision_height(),
                                "Dropping protocol tx from the current proposal",
                            );
                            false
                        }
                        AllocFailure::OverflowsBin { bin_resource} => {
                            // TODO(namada#3250): handle tx whose size is greater
                            // than bin size
                            tracing::warn!(
                                ?tx_bytes,
                                bin_resource,
                                proposal_height =
                                    ?self.get_current_decision_height(),
                                "Dropping large protocol tx from the current proposal",
                            );
                            true
                        }
                    },
                    |()| true,
                )
        )
        .collect();
        // avoid dropping the txs that couldn't be included in the block
        deserialized_iter.keep_rest();
        (alloc, taken)
    }
}

// Validity checks on a wrapper tx
#[allow(clippy::too_many_arguments)]
fn validate_wrapper_bytes<D, H, CA>(
    tx_bytes: &[u8],
    tx_index: TxIndex,
    height: BlockHeight,
    block_time: Option<DateTimeUtc>,
    block_proposer: &Address,
    proposer_local_config: Option<&ValidatorLocalConfig>,
    temp_state: &mut TempWlState<'static, D, H>,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
) -> Result<u64, ()>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
    CA: 'static + WasmCacheAccess + Sync,
{
    let tx = Tx::try_from_bytes(tx_bytes).map_err(|_| ())?;
    let wrapper = tx.header.wrapper().ok_or(())?;

    // If tx doesn't have an expiration it is valid. If time cannot be
    // retrieved from block default to last block datetime which has
    // already been checked by mempool_validate, so it's valid
    if let (Some(block_time), Some(exp)) =
        (block_time.as_ref(), &tx.header().expiration)
    {
        if block_time > exp {
            return Err(());
        }
    }

    // Check tx gas limit for tx size
    let gas_scale = get_gas_scale(temp_state).map_err(|_| ())?;
    let gas_limit =
        wrapper.gas_limit.as_scaled_gas(gas_scale).map_err(|_| ())?;
    let mut tx_gas_meter = TxGasMeter::new(gas_limit, gas_scale);
    tx_gas_meter.add_wrapper_gas(tx_bytes).map_err(|_| ())?;

    super::replay_protection_checks(&tx, temp_state).map_err(|_| ())?;

    // Check fees and extract the gas limit of this transaction
    match prepare_proposal_fee_check(
        &wrapper,
        &tx,
        tx_index,
        height,
        block_proposer,
        proposer_local_config,
        &mut ShellParams::new(
            &RefCell::new(tx_gas_meter),
            temp_state,
            vp_wasm_cache,
            tx_wasm_cache,
        ),
    ) {
        Ok(()) => Ok(u64::from(wrapper.gas_limit)),
        Err(_) => Err(()),
    }
}

fn prepare_proposal_fee_check<D, H, CA>(
    wrapper: &WrapperTx,
    tx: &Tx,
    tx_index: TxIndex,
    height: BlockHeight,
    proposer: &Address,
    proposer_local_config: Option<&ValidatorLocalConfig>,
    shell_params: &mut ShellParams<'_, TempWlState<'static, D, H>, D, H, CA>,
) -> Result<(), Error>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
    CA: 'static + WasmCacheAccess + Sync,
{
    let minimum_gas_price = compute_min_gas_price(
        &wrapper.fee.token,
        proposer_local_config,
        shell_params.state,
    )?;

    super::fee_data_check(wrapper, minimum_gas_price, shell_params)?;

    protocol::transfer_fee(
        shell_params,
        proposer,
        tx,
        wrapper,
        tx_index,
        height,
    )
    .map_or_else(|e| Err(Error::TxApply(e)), |_| Ok(()))
}

fn compute_min_gas_price<D, H>(
    fee_token: &Address,
    proposer_local_config: Option<&ValidatorLocalConfig>,
    temp_state: &TempWlState<'_, D, H>,
) -> Result<Amount, Error>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    #[cfg(not(fuzzing))]
    let consensus_min_gas_price =
        namada_sdk::parameters::read_gas_cost(temp_state, fee_token)
            .expect("Must be able to read gas cost parameter")
            .ok_or_else(|| {
                Error::TxApply(protocol::Error::FeeError(format!(
                    "The provided {fee_token} token is not allowed for fee \
                     payment",
                )))
            })?;
    #[cfg(fuzzing)]
    let consensus_min_gas_price = {
        let _ = temp_state;
        Amount::from_u64(10)
    };

    let Some(config) = proposer_local_config else {
        return Ok(consensus_min_gas_price);
    };

    let validator_min_gas_price = config
        .accepted_gas_tokens
        .get(fee_token)
        .ok_or_else(|| {
            Error::TxApply(protocol::Error::FeeError(format!(
                "The provided {fee_token} token is not accepted by the block \
                 proposer for fee payment",
            )))
        })?
        .to_owned();

    // The validator's local config overrides the consensus param
    // when creating a block, as long as its min gas price for
    // `token` is not lower than the consensus value
    Ok(if validator_min_gas_price < consensus_min_gas_price {
        tracing::warn!(
            fee_token = %fee_token,
            validator_min_gas_price = %DenominatedAmount::from(validator_min_gas_price),
            consensus_min_gas_price = %DenominatedAmount::from(consensus_min_gas_price),
            "The gas price for the given token set by the block proposer \
             is lower than the value agreed upon by consensus. \
             Falling back to consensus value."
        );

        consensus_min_gas_price
    } else {
        validator_min_gas_price
    })
}

#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
#[cfg(test)]
// TODO(namada#3249): write tests for validator set update vote extensions in
// prepare proposals
mod test_prepare_proposal {
    use std::collections::{BTreeMap, BTreeSet};

    use namada_apps_lib::wallet;
    use namada_replay_protection as replay_protection;
    use namada_sdk::ethereum_events::EthereumEvent;
    use namada_sdk::key::RefTo;
    use namada_sdk::proof_of_stake::Epoch;
    use namada_sdk::proof_of_stake::storage::{
        consensus_validator_set_handle,
        read_consensus_validator_set_addresses_with_stake, read_pos_params,
    };
    use namada_sdk::proof_of_stake::types::WeightedValidator;
    use namada_sdk::state::collections::lazy_map::{NestedSubKey, SubKey};
    use namada_sdk::storage::{InnerEthEventsQueue, StorageRead, StorageWrite};
    use namada_sdk::token::read_denom;
    use namada_sdk::tx::data::{Fee, TxType};
    use namada_sdk::tx::{Code, Data, Signed};
    use namada_sdk::{address, governance, token};
    use namada_vote_ext::{ethereum_events, ethereum_tx_data_variants};

    use super::*;
    use crate::shell::EthereumTxData;
    use crate::shell::test_utils::{
        self, TestShell, gen_keypair, get_pkh_from_address,
    };
    use crate::shims::abcipp_shim_types::shim::request::FinalizeBlock;

    /// Check if we are filtering out an invalid vote extension `vext`
    fn check_eth_events_filtering(
        shell: &TestShell,
        vext: Signed<ethereum_events::Vext>,
    ) {
        let tx = EthereumTxData::EthEventsVext(vext.into())
            .sign(
                shell.mode.get_protocol_key().expect("Test failed"),
                shell.chain_id.clone(),
            )
            .to_bytes();
        let rsp = shell.mempool_validate(&tx, Default::default());
        assert!(rsp.code != 0.into(), "{}", rsp.log);
    }

    const GAS_LIMIT: u64 = 50_000;

    /// Test that if a tx from the mempool is not a
    /// WrapperTx type, it is not included in the
    /// proposed block.
    #[test]
    fn test_prepare_proposal_rejects_non_wrapper_tx() {
        let (shell, _recv, _, _) = test_utils::setup();
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();
        tx.header.chain_id = shell.chain_id.clone();
        let req = RequestPrepareProposal {
            txs: vec![tx.to_bytes().into()],
            ..Default::default()
        };
        assert!(shell.prepare_proposal(req).txs.is_empty());
    }

    /// Test that if an error is encountered while
    /// trying to process a tx from the mempool,
    /// we simply exclude it from the proposal
    #[test]
    fn test_error_in_processing_tx() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = gen_keypair();
        // an unsigned wrapper will cause an error in processing
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Default::default(),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                0.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction_data".as_bytes().to_owned()));
        let wrapper = wrapper.to_bytes();
        #[allow(clippy::redundant_clone)]
        let req = RequestPrepareProposal {
            txs: vec![wrapper.clone().into()],
            ..Default::default()
        };
        assert!(shell.prepare_proposal(req).txs.is_empty());
    }

    /// Test if we are filtering out Ethereum events with bad
    /// signatures in a prepare proposal.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_signatures() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);

        let signed_vote_extension = {
            let (protocol_key, _) = wallet::defaults::validator_keys();
            let validator_addr = wallet::defaults::validator_address();

            // generate a valid signature
            let mut ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());

            // modify this signature such that it becomes invalid
            ext.sig = test_utils::invalidate_signature(ext.sig);
            ext
        };

        check_eth_events_filtering(&shell, signed_vote_extension);
    }

    /// Test if we are filtering out Ethereum events seen at
    /// unexpected block heights.
    ///
    /// In case of ABCI++, we should only accept vote extensions
    /// from `last_height`, whereas with ABCI+, vote extensions
    /// before `last_height` are accepted. In either case, vote
    /// extensions after `last_height` aren't accepted.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_bheights() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        fn check_invalid(shell: &TestShell, height: BlockHeight) {
            let (protocol_key, _) = wallet::defaults::validator_keys();
            let validator_addr = wallet::defaults::validator_address();

            let signed_vote_extension = {
                let ext = ethereum_events::Vext {
                    validator_addr,
                    block_height: height,
                    ethereum_events: vec![],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };

            check_eth_events_filtering(shell, signed_vote_extension);
        }

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        assert_eq!(shell.state.in_mem().get_last_block_height(), LAST_HEIGHT);

        check_invalid(&shell, LAST_HEIGHT + 2);
        check_invalid(&shell, LAST_HEIGHT + 1);
        check_invalid(&shell, 0.into());
    }

    /// Test if we are filtering out Ethereum events seen by
    /// non-validator nodes.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_validators() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);

        let (validator_addr, protocol_key) = {
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            (bertha_addr, bertha_key)
        };

        let signed_vote_extension = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        check_eth_events_filtering(&shell, signed_vote_extension);
    }

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering <= 2/3 voting power.
    #[test]
    fn test_prepare_proposal_vext_insufficient_voting_power() {
        use namada_sdk::tendermint::abci::types::{Validator, VoteInfo};

        const FIRST_HEIGHT: BlockHeight = BlockHeight(1);
        const LAST_HEIGHT: BlockHeight = BlockHeight(FIRST_HEIGHT.0 + 11);

        let (mut shell, _recv, _, _oracle_control_recv) =
            test_utils::setup_with_cfg(test_utils::SetupCfg {
                last_height: FIRST_HEIGHT,
                num_validators: 2,
                ..Default::default()
            });

        let params =
            read_pos_params::<_, governance::Store<_>>(&shell.state).unwrap();

        // artificially change the voting power of the default validator to
        // one, change the block height, and commit a dummy block,
        // to move to a new epoch
        let events_epoch = shell
            .state
            .get_epoch_at_height(FIRST_HEIGHT)
            .unwrap()
            .expect("Test failed");
        let validators_handle =
            consensus_validator_set_handle().at(&events_epoch);
        let consensus_in_mem = validators_handle
            .iter(&shell.state)
            .expect("Test failed")
            .map(|val| {
                let (
                    NestedSubKey::Data {
                        key: stake,
                        nested_sub_key: SubKey::Data(position),
                    },
                    address,
                ) = val.expect("Test failed");
                (stake, position, address)
            })
            .collect::<Vec<_>>();

        let mut consensus_set: BTreeSet<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();
        let val1 = consensus_set.pop_first().unwrap();
        let val2 = consensus_set.pop_first().unwrap();
        let pkh1 = get_pkh_from_address(
            &shell.state,
            &params,
            val1.address.clone(),
            Epoch::default(),
        );
        let pkh2 = get_pkh_from_address(
            &shell.state,
            &params,
            val2.address.clone(),
            Epoch::default(),
        );

        for (val_stake, val_position, address) in consensus_in_mem.into_iter() {
            if address == wallet::defaults::validator_address() {
                validators_handle
                    .at(&val_stake)
                    .remove(&mut shell.state, &val_position)
                    .expect("Test failed");
                validators_handle
                    .at(&1.into())
                    .insert(&mut shell.state, val_position, address)
                    .expect("Test failed");
            }
        }
        // Insert some stake for the second validator to prevent total stake
        // from going to 0

        let votes = vec![
            VoteInfo {
                validator: Validator {
                    address: pkh1,
                    power: (u128::try_from(val1.bonded_stake).expect("Test failed") as u64).try_into().unwrap(),
                },
                sig_info: crate::tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh2,
                    power: (u128::try_from(val2.bonded_stake).expect("Test failed") as u64).try_into().unwrap(),
                },
                sig_info: crate::tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
        ];
        let req = FinalizeBlock {
            proposer_address: pkh1.to_vec(),
            decided_last_commit: crate::tendermint::abci::types::CommitInfo {
                round: 0u8.into(),
                votes,
            },
            ..Default::default()
        };
        shell.start_new_epoch(Some(req));
        assert_eq!(
            shell
                .state
                .get_epoch_at_height(shell.get_current_decision_height())
                .unwrap(),
            Some(Epoch(1))
        );

        // test prepare proposal
        let (protocol_key, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let signed_eth_ev_vote_extension = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        let vote = EthereumTxData::EthEventsVext(
            signed_eth_ev_vote_extension.clone().into(),
        )
        .sign(&protocol_key, shell.chain_id.clone())
        .to_bytes();
        let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
            txs: vec![vote.into()],
            ..Default::default()
        });
        assert_eq!(rsp.txs.len(), 1);

        let tx_bytes = rsp.txs.remove(0);
        let got = Tx::try_from_bytes(&tx_bytes[..]).unwrap();
        let eth_tx_data = (&got).try_into().expect("Test failed");
        let rsp_ext = match eth_tx_data {
            EthereumTxData::EthEventsVext(ext) => ext,
            _ => panic!("Test failed"),
        };

        assert_eq!(signed_eth_ev_vote_extension, rsp_ext.0);
    }

    /// Test that if the wrapper tx hash is known (replay attack), the
    /// transaction is not included in the block
    #[test]
    fn test_wrapper_tx_hash() {
        let (mut shell, _recv, _, _) = test_utils::setup();

        let keypair = namada_apps_lib::wallet::defaults::daewon_keypair();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(0.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                0.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(keypair);

        // Write wrapper hash to storage
        let wrapper_unsigned_hash = wrapper.header_hash();
        let hash_key = replay_protection::current_key(&wrapper_unsigned_hash);
        shell
            .state
            .write(&hash_key, Vec::<u8>::new())
            .expect("Test failed");

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes().into()],
            ..Default::default()
        };

        let received_txs = shell.prepare_proposal(req).txs;
        assert_eq!(received_txs.len(), 0);
    }

    /// Test that if two identical wrapper txs are proposed for this block, only
    /// one gets accepted
    #[test]
    fn test_wrapper_tx_hash_same_block() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = namada_apps_lib::wallet::defaults::daewon_keypair();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(keypair);

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes().into(); 2],
            ..Default::default()
        };
        let received_txs = shell.prepare_proposal(req).txs;
        assert_eq!(received_txs.len(), 1);
    }

    /// Test that if the inner tx hash is known (replay attack), the
    /// transaction is not included in the block
    #[test]
    fn test_inner_tx_hash() {
        let (mut shell, _recv, _, _) = test_utils::setup();

        let keypair = namada_apps_lib::wallet::defaults::daewon_keypair();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Amount::zero(),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                0.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(keypair);
        let inner_unsigned_hash = wrapper.raw_header_hash();

        // Write inner hash to storage
        let hash_key = replay_protection::current_key(&inner_unsigned_hash);
        shell
            .state
            .write(&hash_key, Vec::<u8>::new())
            .expect("Test failed");

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes().into()],
            ..Default::default()
        };

        let received_txs = shell.prepare_proposal(req).txs;
        assert_eq!(received_txs.len(), 0);
    }

    /// Test that if two identical inner txs are proposed for this block,
    /// both get accepted
    #[test]
    fn test_inner_tx_hash_same_block() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = namada_apps_lib::wallet::defaults::daewon_keypair();
        let keypair_2 = namada_apps_lib::wallet::defaults::albert_keypair();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        let tx_code = Code::new("wasm_code".as_bytes().to_owned(), None);
        wrapper.set_code(tx_code);
        let tx_data = Data::new("transaction data".as_bytes().to_owned());
        wrapper.set_data(tx_data);
        let mut new_wrapper = wrapper.clone();
        wrapper.sign_wrapper(keypair);

        new_wrapper.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(100.into()),
                token: shell.state.in_mem().native_token.clone(),
            },
            keypair_2.ref_to(),
            GAS_LIMIT.into(),
        ))));
        new_wrapper.sign_wrapper(keypair_2);

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes().into(), new_wrapper.to_bytes().into()],
            ..Default::default()
        };
        let received_txs = shell.prepare_proposal(req).txs;
        assert_eq!(received_txs.len(), 2);
    }

    /// Test that expired wrapper transactions are not included in the block
    #[test]
    fn test_expired_wrapper_tx() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = gen_keypair();
        let mut wrapper_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                0.into(),
            ))));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.header.expiration = Some(DateTimeUtc::default());
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.sign_wrapper(keypair);

        #[allow(clippy::disallowed_methods)]
        let time = DateTimeUtc::now();
        let block_time =
            namada_sdk::tendermint_proto::google::protobuf::Timestamp {
                seconds: time.0.timestamp(),
                nanos: time.0.timestamp_subsec_nanos() as i32,
            };
        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: Some(block_time),
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert_eq!(result.txs.len(), 0);
    }

    /// Check that a tx requiring more gas than the block limit is not included
    /// in the block
    #[test]
    fn test_exceeding_max_block_gas_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let block_gas_limit =
            namada_sdk::parameters::get_max_block_gas(&shell.state).unwrap();
        let keypair = gen_keypair();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(100.into()),
                token: shell.state.in_mem().native_token.clone(),
            },
            keypair.ref_to(),
            (block_gas_limit + 1).into(),
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.sign_wrapper(keypair);

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert!(result.txs.is_empty());
    }

    /// Check that a tx requiring more gas than available in the block is not
    /// included
    #[test]
    fn test_exceeding_available_block_gas_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let block_gas_limit =
            namada_sdk::parameters::get_max_block_gas(&shell.state).unwrap();
        let keypair = namada_apps_lib::wallet::defaults::albert_keypair();

        let mut txs = vec![];
        for _ in 0..2 {
            let mut wrapper =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            100.into(),
                        ),
                        token: shell.state.in_mem().native_token.clone(),
                    },
                    keypair.ref_to(),
                    (block_gas_limit + 1).div_ceil(2).into(),
                ))));
            wrapper.header.chain_id = shell.chain_id.clone();
            wrapper
                .set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
            wrapper
                .set_data(Data::new("transaction data".as_bytes().to_owned()));
            wrapper.sign_wrapper(keypair.clone());
            txs.push(wrapper.to_bytes().into());
        }

        let req = RequestPrepareProposal {
            txs,
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert_eq!(result.txs.len(), 1);
    }

    // Check that a wrapper requiring more gas than its limit is not included in
    // the block
    #[test]
    fn test_exceeding_gas_limit_wrapper() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = gen_keypair();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(100.into()),
                token: shell.state.in_mem().native_token.clone(),
            },
            keypair.ref_to(),
            0.into(),
        );

        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.sign_wrapper(keypair);

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper using a token not accepted by the validator for fee
    // payment is not included in the block
    #[test]
    fn test_fee_non_accepted_token() {
        let (mut shell, _recv, _, _) = test_utils::setup();
        // Update local validator configuration for gas tokens
        if let ShellMode::Validator {
            validator_local_config,
            ..
        } = &mut shell.mode
        {
            // Remove the allowed btc
            *validator_local_config = Some(ValidatorLocalConfig {
                accepted_gas_tokens: namada_sdk::collections::HashMap::from([
                    (namada_sdk::address::testing::nam(), Amount::from(1)),
                ]),
            });
        }

        let btc_denom = read_denom(&shell.state, &address::testing::btc())
            .expect("unable to read denomination from storage")
            .expect("unable to find denomination of btcs");

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::new(
                    100.into(),
                    btc_denom,
                ),
                token: address::testing::btc(),
            },
            namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
            GAS_LIMIT.into(),
        );

        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper using a non-whitelisted token for fee payment is not
    // included in the block
    #[test]
    fn test_fee_non_whitelisted_token() {
        let (shell, _recv, _, _) = test_utils::setup();

        let apfel_denom = read_denom(&shell.state, &address::testing::apfel())
            .expect("unable to read denomination from storage")
            .expect("unable to find denomination of apfels");

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::new(
                    100.into(),
                    apfel_denom,
                ),
                token: address::testing::apfel(),
            },
            namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
            GAS_LIMIT.into(),
        );

        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper using a whitelisted non-native token for fee payment
    // is included in the block
    #[test]
    fn test_fee_whitelisted_non_native_token() {
        let (mut shell, _recv, _, _) = test_utils::setup();

        let apfel_denom = read_denom(&shell.state, &address::testing::apfel())
            .expect("unable to read denomination from storage")
            .expect("unable to find denomination of apfels");
        let fee_amount: token::Amount = GAS_LIMIT.into();

        // Credit some tokens for fee payment
        namada_sdk::token::credit_tokens(
            &mut shell.state,
            &address::testing::apfel(),
            &Address::from(&wallet::defaults::albert_keypair().to_public()),
            fee_amount,
        )
        .unwrap();
        let balance = token::read_balance(
            &shell.state,
            &address::testing::apfel(),
            &Address::from(&wallet::defaults::albert_keypair().to_public()),
        )
        .unwrap();
        assert_eq!(balance, fee_amount.clone());

        // Whitelist Apfel for fee payment
        let gas_cost_key = namada_sdk::parameters::storage::get_gas_cost_key();
        let mut gas_prices: BTreeMap<Address, token::Amount> =
            shell.read_storage_key(&gas_cost_key).unwrap();
        gas_prices.insert(address::testing::apfel(), 1.into());
        shell.shell.state.write(&gas_cost_key, gas_prices).unwrap();
        shell.commit();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::new(
                    1.into(),
                    apfel_denom,
                ),
                token: address::testing::apfel(),
            },
            namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
            GAS_LIMIT.into(),
        );

        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert_eq!(result.txs.first().unwrap(), &wrapper_tx.to_bytes());
    }

    // Check that a wrapper setting a fee amount lower than the minimum accepted
    // by the validator is not included in the block
    #[test]
    fn test_fee_wrong_minimum_accepted_amount() {
        let (mut shell, _recv, _, _) = test_utils::setup();
        // Update local validator configuration for gas tokens
        if let ShellMode::Validator {
            validator_local_config,
            ..
        } = &mut shell.mode
        {
            // Remove btc and increase minimum for nam
            *validator_local_config = Some(ValidatorLocalConfig {
                accepted_gas_tokens: namada_sdk::collections::HashMap::from([
                    (namada_sdk::address::testing::nam(), Amount::from(100)),
                ]),
            });
        }

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(10.into()),
                token: shell.state.in_mem().native_token.clone(),
            },
            namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
            GAS_LIMIT.into(),
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper setting a fee amount lower than the minimum allowed
    // is not included in the block
    #[test]
    fn test_fee_wrong_minimum_amount() {
        let (shell, _recv, _, _) = test_utils::setup();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(0.into()),
                token: shell.state.in_mem().native_token.clone(),
            },
            namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
            GAS_LIMIT.into(),
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper transactions whose fees cannot be paid is rejected
    #[test]
    fn test_insufficient_balance_for_fee() {
        let (shell, _recv, _, _) = test_utils::setup();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(
                    1_000_000_000.into(),
                ),
                token: shell.state.in_mem().native_token.clone(),
            },
            namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
            GAS_LIMIT.into(),
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert!(result.txs.is_empty());
    }

    // Check that a fee overflow in the wrapper transaction is rejected
    #[test]
    fn test_wrapper_fee_overflow() {
        let (shell, _recv, _, _) = test_utils::setup();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(
                    token::Amount::max(),
                ),
                token: shell.state.in_mem().native_token.clone(),
            },
            namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
            GAS_LIMIT.into(),
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        assert!(result.txs.is_empty());
    }

    /// Test that Ethereum events with outdated nonces are
    /// not proposed during `PrepareProposal`.
    #[test]
    fn test_outdated_nonce_proposal() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        shell
            .state
            .in_mem_mut()
            .eth_events_queue
            // sent transfers to namada nonce to 5
            .transfers_to_namada = InnerEthEventsQueue::new_at(5.into());

        let (protocol_key, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        // test an extension containing solely events with
        // bad nonces
        {
            let ethereum_event = EthereumEvent::TransfersToNamada {
                // outdated nonce (3 < 5)
                nonce: 3u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr: validator_addr.clone(),
                    block_height: LAST_HEIGHT,
                    ethereum_events: vec![ethereum_event],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            let tx = EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone())
                .to_bytes();
            let req = RequestPrepareProposal {
                txs: vec![tx.into()],
                ..Default::default()
            };
            let proposed_txs =
                shell.prepare_proposal(req).txs.into_iter().map(|tx_bytes| {
                    Tx::try_from_bytes(tx_bytes.as_ref()).expect("Test failed")
                });
            // since no events with valid nonces are contained in the vote
            // extension, we drop it from the proposal
            for tx in proposed_txs {
                if ethereum_tx_data_variants::EthEventsVext::try_from(&tx)
                    .is_ok()
                {
                    panic!(
                        "No ethereum events should have been found in the \
                         proposal"
                    );
                }
            }
        }

        // test an extension containing at least one event
        // with a good nonce
        {
            let event1 = EthereumEvent::TransfersToNamada {
                // outdated nonce (3 < 5)
                nonce: 3u64.into(),
                transfers: vec![],
            };
            let event2 = EthereumEvent::TransfersToNamada {
                // outdated nonce (10 >= 5)
                nonce: 10u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr,
                    block_height: LAST_HEIGHT,
                    ethereum_events: vec![event1, event2.clone()],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            let tx = EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone())
                .to_bytes();
            let req = RequestPrepareProposal {
                txs: vec![tx.into()],
                ..Default::default()
            };
            let proposed_txs =
                shell.prepare_proposal(req).txs.into_iter().map(|tx_bytes| {
                    Tx::try_from_bytes(tx_bytes.as_ref()).expect("Test failed")
                });
            // find the event with the good nonce
            let mut ext = 'ext: {
                for tx in proposed_txs {
                    if let Ok(ext) =
                        ethereum_tx_data_variants::EthEventsVext::try_from(&tx)
                    {
                        break 'ext ext;
                    }
                }
                panic!("No ethereum events found in proposal");
            };
            assert_eq!(ext.data.ethereum_events.len(), 2);
            let found_event = ext.0.data.ethereum_events.remove(1);
            assert_eq!(found_event, event2);
        }
    }

    /// Test that if a validator's local config minimum
    /// gas price is lower than the consensus value, the
    /// validator defaults to the latter.
    #[test]
    fn test_default_validator_min_gas_price() {
        let (shell, _recv, _, _) = test_utils::setup();
        let temp_state = shell.state.with_temp_write_log();

        let validator_min_gas_price = Amount::zero();
        let consensus_min_gas_price = namada_sdk::parameters::read_gas_cost(
            &temp_state,
            &shell.state.in_mem().native_token,
        )
        .expect("Must be able to read gas cost parameter")
        .expect("NAM should be an allowed gas token");

        assert!(validator_min_gas_price < consensus_min_gas_price);

        let config = ValidatorLocalConfig {
            accepted_gas_tokens: {
                let mut m = namada_sdk::collections::HashMap::new();
                m.insert(
                    shell.state.in_mem().native_token.clone(),
                    validator_min_gas_price,
                );
                m
            },
        };
        let computed_min_gas_price = compute_min_gas_price(
            &shell.state.in_mem().native_token,
            Some(&config),
            &temp_state,
        )
        .unwrap();

        assert_eq!(computed_min_gas_price, consensus_min_gas_price);
    }
}
