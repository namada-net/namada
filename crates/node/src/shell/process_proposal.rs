//! Implementation of the ['VerifyHeader`], [`ProcessProposal`],
//! and [`RevertProposal`] ABCI++ methods for the Shell

use data_encoding::HEXUPPER;
use namada_sdk::parameters;
use namada_sdk::proof_of_stake::storage::find_validator_by_raw_hash;
use namada_sdk::tx::data::protocol::ProtocolTxType;
use namada_vote_ext::ethereum_tx_data_variants;

use super::block_alloc::{BlockGas, BlockSpace};
use super::*;
use crate::shell::block_alloc::{AllocFailure, TxBin};
use crate::shims::abcipp_shim_types::shim::TxBytes;
use crate::shims::abcipp_shim_types::shim::response::ProcessProposal;
use crate::tendermint_proto::abci::RequestProcessProposal;

/// Validation metadata, to keep track of used resources or
/// transaction numbers, in a block proposal.
#[derive(Default)]
pub struct ValidationMeta {
    /// Gas emitted by users.
    pub user_gas: TxBin<BlockGas>,
    /// Space utilized by all txs.
    pub txs_bin: TxBin<BlockSpace>,
}

impl<D, H> From<&WlState<D, H>> for ValidationMeta
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn from(state: &WlState<D, H>) -> Self {
        let max_proposal_bytes = parameters::read_max_proposal_bytes(state)
            .expect("Must be able to read ProposalBytes from storage");
        let max_block_gas = parameters::get_max_block_gas(state).unwrap();

        let user_gas = TxBin::init(max_block_gas);
        let txs_bin = TxBin::init(max_proposal_bytes.get());
        Self { user_gas, txs_bin }
    }
}

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// INVARIANT: This method must be stateless.
    pub fn verify_header(
        &self,
        _req: shim::request::VerifyHeader,
    ) -> shim::response::VerifyHeader {
        Default::default()
    }

    /// Check all the txs in a block. Some txs may be incorrect,
    /// but we only reject the entire block if the order of the
    /// included txs violates the order decided upon in the previous
    /// block.
    pub fn process_proposal(
        &self,
        req: RequestProcessProposal,
    ) -> (ProcessProposal, Vec<TxResult>) {
        tracing::info!(
            proposer = ?HEXUPPER.encode(&req.proposer_address),
            height = req.height,
            hash = ?HEXUPPER.encode(&req.hash),
            n_txs = req.txs.len(),
            "Received block proposal",
        );
        let native_block_proposer_address = {
            let tm_raw_hash_string =
                tm_raw_hash_to_string(&req.proposer_address);
            find_validator_by_raw_hash(&self.state, tm_raw_hash_string)
                .unwrap()
                .expect(
                    "Unable to find native validator address of block \
                     proposer from tendermint raw hash",
                )
        };

        let tx_results = self.process_txs(
            &req.txs,
            req.time
                .expect("Missing timestamp in proposed block")
                .try_into()
                .expect("Failed conversion of Comet timestamp"),
            &native_block_proposer_address,
        );

        // Erroneous transactions were detected when processing
        // the leader's proposal. We allow txs that are invalid at runtime
        // (wasm) to reach FinalizeBlock.
        let invalid_txs = tx_results.iter().any(|res| {
            let error = ResultCode::from_u32(res.code).expect(
                "All error codes returned from process_single_tx are valid",
            );
            !error.is_recoverable()
        });
        if invalid_txs {
            tracing::warn!(
                proposer = ?HEXUPPER.encode(&req.proposer_address),
                height = req.height,
                hash = ?HEXUPPER.encode(&req.hash),
                "Found invalid transactions, proposed block will be rejected"
            );
        }
        (
            if invalid_txs {
                ProcessProposal::Reject
            } else {
                ProcessProposal::Accept
            },
            tx_results,
        )
    }

    /// Evaluates the corresponding [`TxResult`] for each tx in the
    /// proposal.
    ///
    /// `ProcessProposal` should be able to make a decision on whether a
    /// proposed block is acceptable or not based solely on what this
    /// function returns.
    pub fn process_txs(
        &self,
        txs: &[TxBytes],
        block_time: DateTimeUtc,
        block_proposer: &Address,
    ) -> Vec<TxResult> {
        // This is safe as neither the inner `db` nor `in_mem` are
        // actually mutable, only the `write_log` which is owned by
        // the `TempWlState` struct. The `TempWlState` will be dropped
        // before any other ABCI request is processed.
        let mut temp_state = unsafe { self.state.with_static_temp_write_log() };
        let mut metadata = ValidationMeta::from(self.state.read_only());
        let mut vp_wasm_cache = self.vp_wasm_cache.clone();
        let mut tx_wasm_cache = self.tx_wasm_cache.clone();

        let tx_results: Vec<_> = txs
            .iter()
            .enumerate()
            .map(|(tx_index, tx_bytes)| {
                let result = self.check_proposal_tx(
                    tx_bytes,
                    TxIndex::must_from_usize(tx_index),
                    &mut metadata,
                    &mut temp_state,
                    block_time,
                    &mut vp_wasm_cache,
                    &mut tx_wasm_cache,
                    block_proposer,
                );
                let error_code = ResultCode::from_u32(result.code).unwrap();
                if let ResultCode::Ok = error_code {
                    temp_state.write_log_mut().commit_batch_and_current_tx();
                } else {
                    tracing::info!(
                        "Process proposal rejected an invalid tx. Error code: \
                         {:?}, info: {}",
                        error_code,
                        result.info
                    );
                    temp_state.write_log_mut().drop_batch();
                }
                result
            })
            .collect();
        tx_results
    }

    /// Checks if the Tx can be deserialized from bytes. Checks the fees and
    /// signatures of the fee payer for a transaction if it is a wrapper tx.
    ///
    /// Checks validity of an inner tx.
    ///
    /// Error codes:
    ///   0: Ok
    ///   1: Wasm runtime error
    ///   2: Invalid tx
    ///   3: Tx is invalidly signed
    ///   4: Block is full
    ///   5: Replay attempt
    ///   6. Tx targets a different chain id
    ///   7. Tx is expired
    ///   8. Tx exceeds the gas limit
    ///   9. Tx failed to pay fees
    ///   10. An error in the vote extensions included in the proposal
    ///   11. Not enough block space was available for some tx
    ///   12. Tx wasm code is not allowlisted
    ///
    /// INVARIANT: This function should not, under any circumstances, modify the
    /// state since the proposal could be rejected.
    #[allow(clippy::too_many_arguments)]
    pub fn check_proposal_tx<CA>(
        &self,
        tx_bytes: &[u8],
        tx_index: TxIndex,
        metadata: &mut ValidationMeta,
        temp_state: &mut TempWlState<'static, D, H>,
        block_time: DateTimeUtc,
        vp_wasm_cache: &mut VpCache<CA>,
        tx_wasm_cache: &mut TxCache<CA>,
        block_proposer: &Address,
    ) -> TxResult
    where
        CA: 'static + WasmCacheAccess + Sync,
    {
        // check tx bytes
        //
        // NB: always keep this as the first tx check,
        // as it is a pretty cheap one
        if !validate_tx_bytes(&self.state, tx_bytes.len())
            .expect("Failed to get max tx bytes param from storage")
        {
            return TxResult {
                code: ResultCode::TooLarge.into(),
                info: "Tx too large".into(),
            };
        }

        // try to allocate space for this tx
        if let Err(e) = metadata.txs_bin.try_dump(tx_bytes) {
            return TxResult {
                code: ResultCode::AllocationError.into(),
                info: match e {
                    AllocFailure::Rejected { .. } => {
                        "No more space left in the block"
                    }
                    AllocFailure::OverflowsBin { .. } => {
                        "The given tx is larger than the max configured \
                         proposal size"
                    }
                }
                .into(),
            };
        }

        let maybe_tx = Tx::try_from_bytes(tx_bytes).map_or_else(
            |err| {
                tracing::debug!(
                    ?err,
                    "Couldn't deserialize transaction received during \
                     PrepareProposal"
                );
                Err(TxResult {
                    code: ResultCode::InvalidTx.into(),
                    info: "The submitted transaction was not deserializable"
                        .into(),
                })
            },
            |tx| {
                let tx_chain_id = tx.header.chain_id.clone();
                let tx_expiration = tx.header.expiration;
                match tx.validate_tx() {
                    Ok(_) => Ok((tx_chain_id, tx_expiration, tx)),
                    // This occurs if the wrapper / protocol tx signature is
                    // invalid
                    Err(err) => Err(TxResult {
                        code: ResultCode::InvalidSig.into(),
                        info: err.to_string(),
                    }),
                }
            },
        );
        let (tx_chain_id, tx_expiration, tx) = match maybe_tx {
            Ok(tx) => tx,
            Err(tx_result) => return tx_result,
        };

        match tx.header().tx_type {
            // If it is a raw transaction, we do no further validation
            TxType::Raw => TxResult {
                code: ResultCode::InvalidTx.into(),
                info: "Transaction rejected: Raw transactions are not \
                       supported"
                    .into(),
            },
            TxType::Protocol(protocol_tx) => {
                // Tx chain id
                if tx_chain_id != self.chain_id {
                    return TxResult {
                        code: ResultCode::InvalidChainId.into(),
                        info: format!(
                            "Tx carries a wrong chain id: expected {}, found \
                             {}",
                            self.chain_id, tx_chain_id
                        ),
                    };
                }

                // Tx expiration
                if let Some(exp) = tx_expiration {
                    if block_time > exp {
                        return TxResult {
                            code: ResultCode::ExpiredTx.into(),
                            info: format!(
                                "Tx expired at {:#?}, block time: {:#?}",
                                exp, block_time
                            ),
                        };
                    }
                }

                match protocol_tx.tx {
                    ProtocolTxType::EthEventsVext => {
                        ethereum_tx_data_variants::EthEventsVext::try_from(&tx)
                            .map_err(|err| err.to_string())
                            .and_then(|ext| {
                                validate_eth_events_vext::<
                                    _,
                                    _,
                                    governance::Store<_>,
                                >(
                                    &self.state,
                                    &ext.0,
                                    self.state.in_mem().get_last_block_height(),
                                )
                                .map(|_| TxResult {
                                    code: ResultCode::Ok.into(),
                                    info: "Process Proposal accepted this \
                                           transaction"
                                        .into(),
                                })
                                .map_err(|err| err.to_string())
                            })
                            .unwrap_or_else(|err| TxResult {
                                code: ResultCode::InvalidVoteExtension.into(),
                                info: format!(
                                    "Process proposal rejected this proposal \
                                     because one of the included Ethereum \
                                     events vote extensions was invalid: {err}"
                                ),
                            })
                    }
                    ProtocolTxType::BridgePoolVext => {
                        ethereum_tx_data_variants::BridgePoolVext::try_from(&tx)
                            .map_err(|err| err.to_string())
                            .and_then(|ext| {
                                validate_bp_roots_vext::<
                                    _,
                                    _,
                                    governance::Store<_>,
                                >(
                                    &self.state,
                                    &ext.0,
                                    self.state.in_mem().get_last_block_height(),
                                )
                                .map(|_| TxResult {
                                    code: ResultCode::Ok.into(),
                                    info: "Process Proposal accepted this \
                                           transaction"
                                        .into(),
                                })
                                .map_err(|err| err.to_string())
                            })
                            .unwrap_or_else(|err| TxResult {
                                code: ResultCode::InvalidVoteExtension.into(),
                                info: format!(
                                    "Process proposal rejected this proposal \
                                     because one of the included Bridge pool \
                                     root's vote extensions was invalid: {err}"
                                ),
                            })
                    }
                    ProtocolTxType::ValSetUpdateVext => {
                        ethereum_tx_data_variants::ValSetUpdateVext::try_from(
                            &tx,
                        )
                        .map_err(|err| err.to_string())
                        .and_then(|ext| {
                            validate_valset_upd_vext::<_, _, governance::Store<_>>(
                                &self.state,
                                &ext,
                                // n.b. only accept validator set updates
                                // issued at
                                // the current epoch (signing off on the
                                // validators
                                // of the next epoch)
                                self.state.in_mem().get_current_epoch().0,
                            )
                            .map(|_| TxResult {
                                code: ResultCode::Ok.into(),
                                info: "Process Proposal accepted this \
                                       transaction"
                                    .into(),
                            })
                            .map_err(|err| err.to_string())
                        })
                        .unwrap_or_else(|err| {
                            TxResult {
                                code: ResultCode::InvalidVoteExtension.into(),
                                info: format!(
                                    "Process proposal rejected this proposal \
                                     because one of the included validator \
                                     set update vote extensions was invalid: \
                                     {err}"
                                ),
                            }
                        })
                    }
                    ProtocolTxType::EthereumEvents
                    | ProtocolTxType::BridgePool
                    | ProtocolTxType::ValidatorSetUpdate => TxResult {
                        code: ResultCode::InvalidVoteExtension.into(),
                        info: "Process proposal rejected this proposal \
                               because one of the included vote extensions \
                               was invalid: ABCI++ code paths are unreachable \
                               in Namada"
                            .to_string(),
                    },
                }
            }
            TxType::Wrapper(wrapper) => {
                // Validate wrapper first
                // Account for the tx's resources
                let allocated_gas =
                    metadata.user_gas.try_dump(u64::from(wrapper.gas_limit));

                let gas_scale = match get_gas_scale(temp_state) {
                    Ok(scale) => scale,
                    Err(_) => {
                        return TxResult {
                            code: ResultCode::TxGasLimit.into(),
                            info: "Failed to get gas scale".to_owned(),
                        };
                    }
                };
                let gas_limit = match wrapper.gas_limit.as_scaled_gas(gas_scale)
                {
                    Ok(value) => value,
                    Err(_) => {
                        return TxResult {
                            code: ResultCode::InvalidTx.into(),
                            info: "The wrapper gas limit overflowed gas \
                                   representation"
                                .to_owned(),
                        };
                    }
                };
                let mut tx_gas_meter = TxGasMeter::new(gas_limit, gas_scale);
                if tx_gas_meter.add_wrapper_gas(tx_bytes).is_err() {
                    return TxResult {
                        code: ResultCode::TxGasLimit.into(),
                        info: "Wrapper transaction exceeds its gas limit"
                            .to_string(),
                    };
                }
                if let Err(e) = allocated_gas {
                    let info = match e {
                        AllocFailure::Rejected { bin_resource_left } => {
                            format!(
                                "Wrapper transaction exceeds the remaining \
                                 available gas in the block: {}",
                                bin_resource_left
                            )
                        }
                        AllocFailure::OverflowsBin { bin_resource } => format!(
                            "Wrapper transaction exceeds the maximum block \
                             gas limit: {}",
                            bin_resource
                        ),
                    };
                    return TxResult {
                        code: ResultCode::AllocationError.into(),
                        info,
                    };
                };

                // ChainId check
                if tx_chain_id != self.chain_id {
                    return TxResult {
                        code: ResultCode::InvalidChainId.into(),
                        info: format!(
                            "Tx carries a wrong chain id: expected {}, found \
                             {}",
                            self.chain_id, tx_chain_id
                        ),
                    };
                }

                // Tx section count check
                if tx.sections.len() > MAX_TX_SECTIONS_LEN {
                    return TxResult {
                        code: ResultCode::InvalidTx.into(),
                        info: format!(
                            "Tx contains more than {MAX_TX_SECTIONS_LEN} \
                             sections."
                        ),
                    };
                }

                // Tx expiration
                if let Some(exp) = tx_expiration {
                    if block_time > exp {
                        return TxResult {
                            code: ResultCode::ExpiredTx.into(),
                            info: format!(
                                "Tx expired at {:#?}, block time: {:#?}",
                                exp, block_time
                            ),
                        };
                    }
                }

                // Replay protection checks
                if let Err(e) = super::replay_protection_checks(&tx, temp_state)
                {
                    return TxResult {
                        code: ResultCode::ReplayTx.into(),
                        info: e.to_string(),
                    };
                }

                // Validate the inner txs after. Even if the batch is non-atomic
                // we still reject it if just one of the inner txs is
                // invalid
                for cmt in tx.commitments() {
                    // Tx allowlist
                    if let Err(err) =
                        check_tx_allowed(&tx.batch_ref_tx(cmt), &self.state)
                    {
                        return TxResult {
                            code: ResultCode::TxNotAllowlisted.into(),
                            info: format!(
                                "Tx code didn't pass the allowlist check: {}",
                                err
                            ),
                        };
                    }
                }

                // Check that the fee payer has sufficient balance.
                if let Err(e) = process_proposal_fee_check(
                    &wrapper,
                    &tx,
                    tx_index,
                    self.get_current_decision_height(),
                    block_proposer,
                    &mut ShellParams::new(
                        &RefCell::new(tx_gas_meter),
                        temp_state,
                        vp_wasm_cache,
                        tx_wasm_cache,
                    ),
                ) {
                    return TxResult {
                        code: ResultCode::FeeError.into(),
                        info: e.to_string(),
                    };
                }

                TxResult {
                    code: ResultCode::Ok.into(),
                    info: "Process proposal accepted this transaction".into(),
                }
            }
        }
    }

    pub fn revert_proposal(
        &mut self,
        _req: shim::request::RevertProposal,
    ) -> shim::response::RevertProposal {
        Default::default()
    }
}

fn process_proposal_fee_check<D, H, CA>(
    wrapper: &WrapperTx,
    tx: &Tx,
    tx_index: TxIndex,
    height: BlockHeight,
    proposer: &Address,
    shell_params: &mut ShellParams<'_, TempWlState<'static, D, H>, D, H, CA>,
) -> ShellResult<()>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
    CA: 'static + WasmCacheAccess + Sync,
{
    let minimum_gas_price =
        parameters::read_gas_cost(shell_params.state, &wrapper.fee.token)
            .expect("Must be able to read gas cost parameter")
            .ok_or(Error::TxApply(protocol::Error::FeeError(format!(
                "The provided {} token is not allowed for fee payment",
                wrapper.fee.token
            ))))?;

    fee_data_check(wrapper, minimum_gas_price, shell_params)?;

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

/// We test the failure cases of [`process_proposal`]. The happy flows
/// are covered by the e2e tests.
// TODO(namada#3249): write tests for validator set update vote extensions in
// process proposals
#[cfg(test)]
mod test_process_proposal {
    use std::collections::BTreeMap;

    use namada_apps_lib::wallet;
    use namada_replay_protection as replay_protection;
    use namada_sdk::address;
    use namada_sdk::eth_bridge::storage::eth_bridge_queries::{
        EthBridgeQueries, is_bridge_comptime_enabled,
    };
    use namada_sdk::key::*;
    use namada_sdk::state::StorageWrite;
    use namada_sdk::testing::{arb_tampered_wrapper_tx, arb_valid_signed_tx};
    use namada_sdk::token::{Amount, DenominatedAmount, read_denom};
    use namada_sdk::tx::data::Fee;
    use namada_sdk::tx::{Code, Data, Signed};
    use namada_vote_ext::{
        bridge_pool_roots, ethereum_events, validator_set_update,
    };
    use proptest::prop_assert;
    use proptest::test_runner::{Config, TestCaseError, TestRunner};

    use super::*;
    use crate::shell::test_utils::{
        ProcessProposal, TestError, TestShell, deactivate_bridge, gen_keypair,
        get_bp_bytes_to_sign,
    };
    use crate::shims::abcipp_shim_types::shim::request::ProcessedTx;

    const GAS_LIMIT: u64 = 100_000;

    /// Check that we reject a validator set update protocol tx
    /// if the bridge is not active.
    #[test]
    fn check_rejected_valset_upd_bridge_inactive() {
        if is_bridge_comptime_enabled() {
            // NOTE: validator set updates are always signed
            // when the bridge is enabled at compile time
            return;
        }

        let (shell, _, _, _) = test_utils::setup_at_height(3);
        let ext = {
            let eth_hot_key =
                shell.mode.get_eth_bridge_keypair().expect("Test failed");
            let signing_epoch = shell.state.in_mem().get_current_epoch().0;
            let next_epoch = signing_epoch.next();
            let voting_powers = shell
                .state
                .ethbridge_queries()
                .get_consensus_eth_addresses::<governance::Store<_>>(next_epoch)
                .map(|(eth_addr_book, _, voting_power)| {
                    (eth_addr_book, voting_power)
                })
                .collect();
            let validator_addr = shell
                .mode
                .get_validator_address()
                .expect("Test failed")
                .clone();
            let ext = validator_set_update::Vext {
                voting_powers,
                validator_addr,
                signing_epoch,
            };
            ext.sign(eth_hot_key)
        };
        let request = {
            let protocol_key =
                shell.mode.get_protocol_key().expect("Test failed");
            let tx = EthereumTxData::ValSetUpdateVext(ext)
                .sign(protocol_key, shell.chain_id.clone())
                .to_bytes();
            ProcessProposal { txs: vec![tx] }
        };

        let response = if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(request)
        {
            if let [resp] = resp.as_slice() {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        } else {
            panic!("Test failed")
        };
        assert_eq!(
            response.result.code,
            u32::from(ResultCode::InvalidVoteExtension)
        );
    }

    /// Check that we reject an eth events protocol tx
    /// if the bridge is not active.
    #[test]
    fn check_rejected_eth_events_bridge_inactive() {
        let (mut shell, _, _, _) = test_utils::setup_at_height(3);
        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        let addr = shell.mode.get_validator_address().expect("Test failed");
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = ethereum_events::Vext {
            validator_addr: addr.clone(),
            block_height: shell.state.in_mem().get_last_block_height(),
            ethereum_events: vec![event],
        }
        .sign(protocol_key);
        let tx = EthereumTxData::EthEventsVext(ext.into())
            .sign(protocol_key, shell.chain_id.clone())
            .to_bytes();
        let request = ProcessProposal { txs: vec![tx] };

        if is_bridge_comptime_enabled() {
            let [resp]: [ProcessedTx; 1] = shell
                .process_proposal(request.clone())
                .expect("Test failed")
                .try_into()
                .expect("Test failed");
            assert_eq!(resp.result.code, u32::from(ResultCode::Ok));
            deactivate_bridge(&mut shell);
        }
        let response = if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(request)
        {
            if let [resp] = resp.as_slice() {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        } else {
            panic!("Test failed")
        };
        assert_eq!(
            response.result.code,
            u32::from(ResultCode::InvalidVoteExtension)
        );
    }

    /// Check that we reject an bp roots protocol tx
    /// if the bridge is not active.
    #[test]
    fn check_rejected_bp_roots_bridge_inactive() {
        let (mut shell, _a, _b, _c) = test_utils::setup_at_height(1);
        shell.state.in_mem_mut().block.height =
            shell.state.in_mem().get_last_block_height();
        shell.commit();
        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        let addr = shell.mode.get_validator_address().expect("Test failed");
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let vote_ext = bridge_pool_roots::Vext {
            block_height: shell.state.in_mem().get_last_block_height(),
            validator_addr: addr.clone(),
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        let tx = EthereumTxData::BridgePoolVext(vote_ext)
            .sign(protocol_key, shell.chain_id.clone())
            .to_bytes();
        let request = ProcessProposal { txs: vec![tx] };

        if is_bridge_comptime_enabled() {
            let [resp]: [ProcessedTx; 1] = shell
                .process_proposal(request.clone())
                .expect("Test failed")
                .try_into()
                .expect("Test failed");

            assert_eq!(resp.result.code, u32::from(ResultCode::Ok));
            deactivate_bridge(&mut shell);
        }
        let response = if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(request)
        {
            if let [resp] = resp.as_slice() {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        } else {
            panic!("Test failed")
        };
        assert_eq!(
            response.result.code,
            u32::from(ResultCode::InvalidVoteExtension)
        );
    }

    fn check_rejected_eth_events(
        shell: &mut TestShell,
        vote_extension: ethereum_events::SignedVext,
        protocol_key: common::SecretKey,
    ) {
        let tx = EthereumTxData::EthEventsVext(vote_extension)
            .sign(&protocol_key, shell.chain_id.clone())
            .to_bytes();
        let request = ProcessProposal { txs: vec![tx] };
        let response = if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(request)
        {
            if let [resp] = resp.as_slice() {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        } else {
            panic!("Test failed")
        };
        assert_eq!(
            response.result.code,
            u32::from(ResultCode::InvalidVoteExtension)
        );
    }

    /// Test that if a proposal contains Ethereum events with
    /// invalid validator signatures, we reject it.
    #[test]
    fn test_drop_vext_with_invalid_sigs() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        let (protocol_key, _) = wallet::defaults::validator_keys();
        let addr = wallet::defaults::validator_address();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = {
            // generate a valid signature
            #[allow(clippy::redundant_clone)]
            let mut ext = ethereum_events::Vext {
                validator_addr: addr.clone(),
                block_height: LAST_HEIGHT,
                ethereum_events: vec![event.clone()],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());

            // modify this signature such that it becomes invalid
            ext.sig = test_utils::invalidate_signature(ext.sig);
            ext
        };
        check_rejected_eth_events(&mut shell, ext.into(), protocol_key);
    }

    /// Test that if a proposal contains Ethereum events with
    /// invalid block heights, we reject it.
    #[test]
    fn test_drop_vext_with_invalid_bheights() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);
        const INVALID_HEIGHT: BlockHeight = BlockHeight(LAST_HEIGHT.0 + 1);
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        let (protocol_key, _) = wallet::defaults::validator_keys();
        let addr = wallet::defaults::validator_address();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = {
            #[allow(clippy::redundant_clone)]
            let ext = ethereum_events::Vext {
                validator_addr: addr.clone(),
                block_height: INVALID_HEIGHT,
                ethereum_events: vec![event.clone()],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };
        check_rejected_eth_events(&mut shell, ext.into(), protocol_key);
    }

    /// Test that if a proposal contains Ethereum events with
    /// invalid validators, we reject it.
    #[test]
    fn test_drop_vext_with_invalid_validators() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        let (addr, protocol_key) = {
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            (bertha_addr, bertha_key)
        };
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = {
            #[allow(clippy::redundant_clone)]
            let ext = ethereum_events::Vext {
                validator_addr: addr.clone(),
                block_height: LAST_HEIGHT,
                ethereum_events: vec![event.clone()],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };
        check_rejected_eth_events(&mut shell, ext.into(), protocol_key);
    }

    /// Test that if a wrapper tx is not signed, the block is rejected
    /// by [`process_proposal`].
    #[test]
    fn test_unsigned_wrapper_rejected() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();
        let public_key = keypair.ref_to();
        let mut outer_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Default::default(),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                public_key,
                GAS_LIMIT.into(),
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));

        let tx = outer_tx.to_bytes();

        let response = {
            let request = ProcessProposal { txs: vec![tx] };
            if let Err(TestError::RejectProposal(resp)) =
                shell.process_proposal(request)
            {
                if let [resp] = resp.as_slice() {
                    resp.clone()
                } else {
                    panic!("Test failed")
                }
            } else {
                panic!("Test failed")
            }
        };

        println!("{}", response.result.info);

        assert_eq!(response.result.code, u32::from(ResultCode::InvalidSig));
        assert_eq!(
            response.result.info,
            String::from(
                "WrapperTx signature verification failed: The section \
                 signature is invalid: signature threshold not met: (0 < 1)"
            )
        );
    }

    /// Test that a block including a wrapper tx with invalid signature is
    /// rejected
    #[test]
    fn test_wrapper_bad_signature() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);

        let mut runner = TestRunner::new(Config::default());
        // Test that the strategy produces valid txs first
        let result =
            runner.run(&arb_valid_signed_tx(), |tx| match tx.validate_tx() {
                Ok(Some(_)) => Ok(()),
                _ => {
                    Err(TestCaseError::fail("Unexpectedly produced invalid tx"))
                }
            });
        assert!(result.is_ok());

        // Then test invalid tx
        let mut runner = TestRunner::new(Config::default());
        let result = runner.run(&arb_tampered_wrapper_tx(), |tx| {
            let request = ProcessProposal {
                txs: vec![tx.to_bytes()],
            };

            match shell.process_proposal(request) {
                Ok(_) => Err(TestCaseError::fail(
                    "Tampered transaction was mistakenly accepted",
                )),
                Err(TestError::RejectProposal(response)) => {
                    let response = if let [response] = response.as_slice() {
                        response.clone()
                    } else {
                        return Err(TestCaseError::fail("Missing tx result"));
                    };
                    prop_assert!(
                        response.result.code
                            == u32::from(ResultCode::InvalidTx)
                            || response.result.code
                                == u32::from(ResultCode::InvalidSig)
                    );

                    Ok(())
                }
            }
        });
        assert!(result.is_ok());
    }

    /// Test that an implicit account does not need to reveal the pk for fee
    /// payment
    #[test]
    fn test_wrapper_unknown_address() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();
        let address = Address::from(&keypair.ref_to());
        let balance_key = token::storage_key::balance_key(
            &shell.state.in_mem().native_token,
            &address,
        );
        shell
            .state
            .write(&balance_key, Amount::native_whole(GAS_LIMIT))
            .unwrap();
        shell.commit();
        // Verify that the public key associated with the fee payer has not been
        // revealed
        assert!(
            namada_sdk::account::public_keys(&shell.state, &address)
                .unwrap()
                .is_empty()
        );
        let mut outer_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                GAS_LIMIT.into(),
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        outer_tx.sign_wrapper(keypair);

        let request = ProcessProposal {
            txs: vec![outer_tx.to_bytes()],
        };
        let response = shell.process_proposal(request).unwrap();
        assert_eq!(response[0].result.code, u32::from(ResultCode::Ok));
    }

    /// Test that if the account submitting the tx does not have sufficient
    /// balance to pay the fee, [`process_proposal`] rejects the entire block
    #[test]
    fn test_wrapper_insufficient_balance_address() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = namada_apps_lib::wallet::defaults::daewon_keypair();
        // reduce address balance to match the 100 token min fee
        let balance_key = token::storage_key::balance_key(
            &shell.state.in_mem().native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .state
            .write(&balance_key, Amount::native_whole(99))
            .unwrap();
        shell.commit();

        let mut outer_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Amount::native_whole(1_000_100),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                GAS_LIMIT.into(),
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        outer_tx.sign_wrapper(keypair);

        let response = {
            let request = ProcessProposal {
                txs: vec![outer_tx.to_bytes()],
            };
            if let Err(TestError::RejectProposal(resp)) =
                shell.process_proposal(request)
            {
                if let [resp] = resp.as_slice() {
                    resp.clone()
                } else {
                    panic!("Test failed")
                }
            } else {
                panic!("Test failed")
            }
        };
        assert_eq!(response.result.code, u32::from(ResultCode::FeeError));
        assert!(response.result.info.contains(
            "Error trying to apply a transaction: Error while processing \
             transaction's fees: The transparent balance of the fee payer was \
             insufficient to pay fees. The protocol tried to run the first \
             transaction in the batch to pay fees via the MASP but it failed: \
             Wasm run failed: Transaction runner error: Wasm validation error"
        ));
    }

    /// Process Proposal should reject a block containing a RawTx, but not panic
    #[test]
    fn test_raw_tx_rejected() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);

        let keypair = namada_apps_lib::wallet::defaults::daewon_keypair();

        let mut tx = Tx::new(shell.chain_id.clone(), None);
        tx.add_code("wasm_code".as_bytes().to_owned(), None)
            .add_data("transaction data".as_bytes().to_owned())
            .sign_wrapper(keypair);

        let response = {
            let request = ProcessProposal {
                txs: vec![tx.to_bytes()],
            };
            if let Err(TestError::RejectProposal(resp)) =
                shell.process_proposal(request)
            {
                if let [resp] = resp.as_slice() {
                    resp.clone()
                } else {
                    panic!("Test failed")
                }
            } else {
                panic!("Test failed")
            }
        };
        assert_eq!(response.result.code, u32::from(ResultCode::InvalidTx));
        assert_eq!(
            response.result.info,
            String::from(
                "Transaction rejected: Raw transactions are not supported"
            ),
        );
    }

    /// Test that if the uwrapper tx hash is known (replay attack), the
    /// block is rejected
    #[test]
    fn test_wrapper_tx_hash() {
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
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.sign_wrapper(keypair);

        // Write wrapper hash to storage
        let mut batch = namada_sdk::state::testing::TestState::batch();
        let wrapper_unsigned_hash = wrapper.header_hash();
        let hash_key = replay_protection::current_key(&wrapper_unsigned_hash);
        shell
            .state
            .write_replay_protection_entry(&mut batch, &hash_key)
            .expect("Test failed");

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };

        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::ReplayTx)
                );
                assert_eq!(
                    response[0].result.info,
                    format!(
                        "Transaction replay attempt: Wrapper transaction hash \
                         {} already in storage",
                        wrapper_unsigned_hash
                    )
                );
            }
        }
    }

    /// Test that a block containing two identical wrapper txs is rejected
    #[test]
    fn test_wrapper_tx_hash_same_block() {
        let (mut shell, _recv, _, _) = test_utils::setup();

        let keypair = namada_apps_lib::wallet::defaults::daewon_keypair();

        // Add unshielded balance for fee payment
        let balance_key = token::storage_key::balance_key(
            &shell.state.in_mem().native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .state
            .write(&balance_key, Amount::native_whole(1000))
            .unwrap();

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

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes(); 2],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(response[0].result.code, u32::from(ResultCode::Ok));
                assert_eq!(
                    response[1].result.code,
                    u32::from(ResultCode::ReplayTx)
                );
                assert_eq!(
                    response[1].result.info,
                    format!(
                        "Transaction replay attempt: Wrapper transaction hash \
                         {} already in storage",
                        wrapper.header_hash()
                    )
                );
            }
        }
    }

    /// Test that if the inner tx hash is known (replay attack), the
    /// block is rejected
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
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(keypair);

        // Write inner hash to storage
        let mut batch = namada_sdk::state::testing::TestState::batch();
        let hash_key =
            replay_protection::current_key(&wrapper.raw_header_hash());
        shell
            .state
            .write_replay_protection_entry(&mut batch, &hash_key)
            .expect("Test failed");

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::ReplayTx)
                );
                assert_eq!(
                    response[0].result.info,
                    format!(
                        "Transaction replay attempt: Batch transaction hash \
                         {} already in storage",
                        wrapper.raw_header_hash()
                    )
                );
            }
        }
    }

    /// Test that a block containing two identical inner transactions is
    /// accepted
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
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
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

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes(), new_wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(received) => assert_eq!(received.len(), 2),
            Err(_) => panic!("Test failed"),
        }
    }

    /// Test that a wrapper or protocol transaction with a mismatching chain id
    /// causes the entire block to be rejected
    #[test]
    fn test_wrong_chain_id() {
        let (shell, _recv, _, _) = test_utils::setup();
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
                GAS_LIMIT.into(),
            ))));
        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        wrapper.header.chain_id = wrong_chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(keypair);

        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        let protocol_tx = EthereumTxData::EthEventsVext({
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            ethereum_events::Vext::empty(1234_u64.into(), bertha_addr)
                .sign(&bertha_key)
                .into()
        })
        .sign(protocol_key, wrong_chain_id.clone());

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes(), protocol_tx.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                for res in response {
                    assert_eq!(
                        res.result.code,
                        u32::from(ResultCode::InvalidChainId)
                    );
                    assert_eq!(
                        res.result.info,
                        format!(
                            "Tx carries a wrong chain id: expected {}, found \
                             {}",
                            shell.chain_id, wrong_chain_id
                        )
                    );
                }
            }
        }
    }

    /// Test that an expired wrapper transaction causes a block rejection
    #[test]
    fn test_expired_wrapper() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = namada_apps_lib::wallet::defaults::daewon_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.header.expiration = Some(DateTimeUtc::default());
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(keypair);

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::ExpiredTx)
                );
            }
        }
    }

    /// Check that a tx requiring more gas than the block limit causes a block
    /// rejection
    #[test]
    fn test_exceeding_max_block_gas_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let block_gas_limit =
            parameters::get_max_block_gas(&shell.state).unwrap();
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                (block_gas_limit + 1).into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(keypair);

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::AllocationError)
                );
            }
        }
    }

    /// Check that a tx requiring more gas than the available gas in the block
    /// causes a block rejection
    #[test]
    fn test_exceeding_available_block_gas_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let block_gas_limit =
            parameters::get_max_block_gas(&shell.state).unwrap();
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
            txs.push(wrapper.to_bytes());
        }

        // Run validation
        let request = ProcessProposal { txs };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(response[0].result.code, u32::from(ResultCode::Ok));
                assert_eq!(
                    response[1].result.code,
                    u32::from(ResultCode::AllocationError)
                );
            }
        }
    }

    // Check that a wrapper requiring more gas than its limit causes a block
    // rejection
    #[test]
    fn test_exceeding_gas_limit_wrapper() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                0.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(keypair);

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::TxGasLimit)
                );
            }
        }
    }

    // Check that a wrapper using a non-whitelisted token for fee payment causes
    // a block rejection
    #[test]
    fn test_fee_non_whitelisted_token() {
        let (shell, _recv, _, _) = test_utils::setup();

        let apfel_denom = read_denom(&shell.state, &address::testing::apfel())
            .expect("unable to read denomination from storage")
            .expect("unable to find denomination of apfels");

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::new(
                        100.into(),
                        apfel_denom,
                    ),
                    token: address::testing::apfel(),
                },
                namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::FeeError)
                );
            }
        }
    }

    // Check that a wrapper using a whitelisted non-native token for fee payment
    // is accepted
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

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::new(
                        1.into(),
                        apfel_denom,
                    ),
                    token: address::testing::apfel(),
                },
                namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        assert!(shell.process_proposal(request).is_ok());
    }

    // Check that a wrapper setting a fee amount lower than the minimum required
    // causes a block rejection
    #[test]
    fn test_fee_wrong_minimum_amount() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(0.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::FeeError)
                );
            }
        }
    }

    // Check that a wrapper transactions whose fees cannot be paid causes a
    // block rejection
    #[test]
    fn test_insufficient_balance_for_fee() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        1_000_000_000.into(),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
                150_000.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::FeeError)
                );
            }
        }
    }

    // Check that a fee overflow in the wrapper transaction causes a block
    // rejection
    #[test]
    fn test_wrapper_fee_overflow() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        token::Amount::max(),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper
            .sign_wrapper(namada_apps_lib::wallet::defaults::albert_keypair());

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::FeeError)
                );
            }
        }
    }

    /// Test max tx bytes parameter in ProcessProposal
    #[test]
    fn test_max_tx_bytes_process_proposal() {
        use parameters::storage::get_max_tx_bytes_key;
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);

        let max_tx_bytes: u32 = {
            let key = get_max_tx_bytes_key();
            shell
                .state
                .read(&key)
                .expect("Failed to read from storage")
                .expect("Max tx bytes should have been written to storage")
        };

        let new_tx = |size: u32| {
            let keypair = super::test_utils::gen_keypair();
            let mut wrapper =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            100.into(),
                        ),
                        token: shell.state.in_mem().native_token.clone(),
                    },
                    keypair.ref_to(),
                    GAS_LIMIT.into(),
                ))));
            wrapper.header.chain_id = shell.chain_id.clone();
            wrapper
                .set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
            wrapper.set_data(Data::new(vec![0; size as usize]));
            wrapper.sign_wrapper(keypair);
            wrapper
        };

        let request = ProcessProposal {
            txs: vec![new_tx(max_tx_bytes + 1).to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::TooLarge)
                );
            }
        }

        let request = ProcessProposal {
            txs: vec![new_tx(0).to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert!(
                    response[0].result.code != u32::from(ResultCode::TooLarge)
                );
            }
        }
    }

    /// Test that Ethereum events with outdated nonces are
    /// not validated by `ProcessProposal`.
    #[test]
    fn test_outdated_nonce_process_proposal() {
        use namada_sdk::storage::InnerEthEventsQueue;

        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }

        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        shell
            .state
            .in_mem_mut()
            .eth_events_queue
            // sent transfers to namada nonce to 5
            .transfers_to_namada = InnerEthEventsQueue::new_at(5.into());

        let (protocol_key, _) = wallet::defaults::validator_keys();

        // only bad events
        {
            let ethereum_event = EthereumEvent::TransfersToNamada {
                // outdated nonce (3 < 5)
                nonce: 3u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr: wallet::defaults::validator_address(),
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
            let req = ProcessProposal { txs: vec![tx] };
            let rsp = shell.process_proposal(req);
            assert!(rsp.is_err());
        }

        // at least one good event
        {
            let e1 = EthereumEvent::TransfersToNamada {
                nonce: 3u64.into(),
                transfers: vec![],
            };
            let e2 = EthereumEvent::TransfersToNamada {
                nonce: 5u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr: wallet::defaults::validator_address(),
                    block_height: LAST_HEIGHT,
                    ethereum_events: vec![e1, e2],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            let tx = EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone())
                .to_bytes();
            let req = ProcessProposal { txs: vec![tx] };
            let rsp = shell.process_proposal(req);
            assert!(rsp.is_ok());
        }
    }

    /// Process Proposal should reject a block containing a tx with a number of
    /// sections exceeding the limit
    #[test]
    fn test_max_sections_exceeded_tx_rejected() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);

        let keypair = namada_apps_lib::wallet::defaults::daewon_keypair();

        // Make a transaction that exceeds the number of max number of allowed
        // sections
        let mut tx = Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(100.into()),
                token: shell.state.in_mem().native_token.clone(),
            },
            keypair.ref_to(),
            (GAS_LIMIT * 10).into(),
        ))));
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));

        // Wrapper sig and header
        const OTHER_SECTIONS: usize = 2;
        for _ in 0..(MAX_TX_SECTIONS_LEN - OTHER_SECTIONS + 1) {
            tx.set_data(Data::new(vec![0]));
        }
        tx.sign_wrapper(keypair);

        assert_eq!(tx.sections.len(), MAX_TX_SECTIONS_LEN + 1);

        let response = {
            let request = ProcessProposal {
                txs: vec![tx.to_bytes()],
            };
            if let Err(TestError::RejectProposal(resp)) =
                shell.process_proposal(request)
            {
                if let [resp] = resp.as_slice() {
                    resp.clone()
                } else {
                    panic!("Test failed")
                }
            } else {
                panic!("Test failed")
            }
        };
        assert_eq!(response.result.code, u32::from(ResultCode::InvalidTx));
        assert_eq!(
            response.result.info,
            format!("Tx contains more than {MAX_TX_SECTIONS_LEN} sections."),
        );
    }
}
