//! Implementation of the `FinalizeBlock` ABCI++ method for the Shell

use data_encoding::HEXUPPER;
use either::Either;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use namada_sdk::events::extend::{ComposeEvent, Height, Info, TxHash};
use namada_sdk::events::{EmitEvents, Event};
use namada_sdk::gas::GasMetering;
use namada_sdk::gas::event::GasUsed;
use namada_sdk::governance::pgf::inflation as pgf_inflation;
use namada_sdk::hash::Hash;
use namada_sdk::parameters::get_gas_scale;
use namada_sdk::proof_of_stake::storage::{
    find_validator_by_raw_hash, write_last_block_proposer_address,
};
use namada_sdk::state::write_log::StorageModification;
use namada_sdk::state::{
    EPOCH_SWITCH_BLOCKS_DELAY, Result, ResultExt, StorageWrite,
};
use namada_sdk::storage::{BlockHeader, BlockResults, Epoch};
use namada_sdk::tx::data::protocol::ProtocolTxType;
use namada_sdk::tx::data::{VpStatusFlags, compute_inner_tx_hash};
use namada_sdk::tx::event::{Batch, Code};
use namada_sdk::tx::new_tx_event;
use namada_sdk::{ibc, proof_of_stake};
use namada_vote_ext::ethereum_events::MultiSignedEthEvent;
use namada_vote_ext::ethereum_tx_data_variants;
use tendermint::abci::types::Misbehavior;

use super::*;
use crate::protocol::{DispatchArgs, DispatchError};
use crate::shell::stats::InternalStats;
use crate::tendermint::abci::types::VoteInfo;
use crate::tendermint_proto;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Updates the chain with new header, height, etc. Also keeps track
    /// of epoch changes and applies associated updates to validator sets,
    /// etc. as necessary.
    ///
    /// Apply the transactions included in the block.
    pub fn finalize_block(
        &mut self,
        req: shim::request::FinalizeBlock,
    ) -> ShellResult<shim::response::FinalizeBlock> {
        let mut response = shim::response::FinalizeBlock::default();

        // Begin the new block and check if a new epoch has begun
        let (height, new_epoch) = self.update_state(req.header);
        let masp_epoch_multiplier =
            parameters::read_masp_epoch_multiplier_parameter(&self.state)
                .expect("Must have parameters");
        let is_masp_new_epoch = self
            .state
            .is_masp_new_epoch(new_epoch, masp_epoch_multiplier)?;

        let (current_epoch, _gas) = self.state.in_mem().get_current_epoch();
        let update_for_tendermint = matches!(
            self.state.in_mem().update_epoch_blocks_delay,
            Some(EPOCH_SWITCH_BLOCKS_DELAY)
        );

        tracing::info!(
            "Block height: {height}, epoch: {current_epoch}, is new epoch: \
             {new_epoch}, is masp new epoch: {is_masp_new_epoch}."
        );
        if update_for_tendermint {
            tracing::info!(
                "Will begin a new epoch {} in {} blocks starting at height {}",
                current_epoch.next(),
                EPOCH_SWITCH_BLOCKS_DELAY,
                height
                    .0
                    .checked_add(u64::from(EPOCH_SWITCH_BLOCKS_DELAY))
                    .expect("Shouldn't overflow")
            );
        }
        tracing::debug!(
            "New epoch block delay for updating the Tendermint validator set: \
             {:?}",
            self.state.in_mem().update_epoch_blocks_delay
        );

        let emit_events = &mut response.events;
        // Get the actual votes from cometBFT in the preferred format
        let votes =
            pos_votes_from_abci(&self.state, &req.decided_last_commit.votes);
        let validator_set_update_epoch =
            self.get_validator_set_update_epoch(current_epoch);
        let gas_scale = get_gas_scale(&self.state)
            .expect("Failed to get gas scale from parameters");

        // Sub-system updates:
        // - Governance - applied first in case a proposal changes any of the
        //   other syb-systems
        gov_finalize_block(
            self,
            emit_events,
            current_epoch,
            new_epoch,
            gas_scale,
        )?;
        // - Token
        token_finalize_block(&mut self.state, emit_events, is_masp_new_epoch)?;
        // - PoS
        //    - Must be applied after governance in case it changes PoS params
        pos_finalize_block(
            &mut self.state,
            emit_events,
            new_epoch,
            validator_set_update_epoch,
            votes,
            req.byzantine_validators,
        )?;
        // - IBC
        ibc::finalize_block(&mut self.state, emit_events, new_epoch)?;

        if new_epoch {
            // Apply PoS and PGF inflation
            self.apply_inflation(current_epoch, emit_events)?;
        }

        let mut stats = InternalStats::default();

        let native_block_proposer_address = {
            let tm_raw_hash_string =
                tm_raw_hash_to_string(req.proposer_address);
            find_validator_by_raw_hash(&self.state, tm_raw_hash_string)
                .unwrap()
                .expect(
                    "Unable to find native validator address of block \
                     proposer from tendermint raw hash",
                )
        };

        // Tracks the accepted transactions
        self.state.in_mem_mut().block.results = BlockResults::default();
        let mut changed_keys = BTreeSet::new();

        // Execute wrapper and protocol transactions
        let successful_wrappers = self.retrieve_and_execute_transactions(
            &native_block_proposer_address,
            &req.txs,
            gas_scale,
            ExecutionArgs {
                response: &mut response,
                changed_keys: &mut changed_keys,
                stats: &mut stats,
                height,
            },
        );

        // Execute inner transactions
        self.execute_tx_batches(
            successful_wrappers,
            ExecutionArgs {
                response: &mut response,
                changed_keys: &mut changed_keys,
                stats: &mut stats,
                height,
            },
        );

        stats.set_tx_cache_size(
            self.tx_wasm_cache.get_size(),
            self.tx_wasm_cache.get_cache_size(),
        );
        stats.set_vp_cache_size(
            self.vp_wasm_cache.get_size(),
            self.vp_wasm_cache.get_cache_size(),
        );

        tracing::info!("{}", stats);
        tracing::info!("{}", stats.format_tx_executed());

        // Update the MASP commitment tree anchor if the tree was updated
        let tree_key = token::storage_key::masp_commitment_tree_key();
        if let Some(StorageModification::Write { value }) = self
            .state
            .write_log()
            .read(&tree_key)
            .expect("Must be able to read masp commitment tree")
            .0
        {
            let updated_tree = CommitmentTree::<Node>::try_from_slice(value)
                .into_storage_result()?;
            let anchor_key = token::storage_key::masp_commitment_anchor_key(
                updated_tree.root(),
            );
            self.state.write(&anchor_key, ())?;
        }

        if update_for_tendermint {
            self.update_epoch(&mut response);
            // send the latest oracle configs. These may have changed due to
            // governance.
            self.update_eth_oracle(&changed_keys);
        }

        write_last_block_proposer_address(
            &mut self.state,
            native_block_proposer_address,
        )?;

        self.event_log_mut().emit_many(response.events.clone());
        tracing::debug!("End finalize_block {height} of epoch {current_epoch}");

        Ok(response)
    }

    /// Sets the metadata necessary for a new block, including the height,
    /// validator changes, and evidence of byzantine behavior. Applies slashes
    /// if necessary. Returns a boolean indicating if a new epoch and the height
    /// of the new block.
    fn update_state(&mut self, header: BlockHeader) -> (BlockHeight, bool) {
        let height = self.state.in_mem().get_last_block_height().next_height();

        self.state
            .in_mem_mut()
            .begin_block(height)
            .expect("Beginning a block shouldn't fail");

        let header_time = header.time;
        self.state
            .in_mem_mut()
            .set_header(header)
            .expect("Setting a header shouldn't fail");

        let parameters =
            parameters::read(&self.state).expect("Must have parameters");
        let new_epoch = self
            .state
            .update_epoch(height, header_time, &parameters)
            .expect("Must be able to update epoch");
        (height, new_epoch)
    }

    fn update_tx_gas(&mut self, tx_hash: Hash, gas: Gas) {
        self.state.in_mem_mut().add_tx_gas(tx_hash, gas);
    }

    /// If a new epoch begins, we update the response to include
    /// changes to the validator sets and consensus parameters
    fn update_epoch(&mut self, response: &mut shim::response::FinalizeBlock) {
        // Apply validator set update
        response.validator_updates = self
            .get_abci_validator_updates(false, |pk, power| {
                let pub_key = tendermint_proto::crypto::PublicKey {
                    sum: Some(key_to_tendermint(&pk).unwrap()),
                };
                let pub_key = Some(pub_key);
                tendermint_proto::abci::ValidatorUpdate { pub_key, power }
            })
            .expect("Must be able to update validator set");
    }

    /// Calculate the new inflation rate, mint the new tokens to the PoS
    /// account, then update the reward products of the validators. This is
    /// executed while finalizing the first block of a new epoch and is applied
    /// with respect to the previous epoch.
    fn apply_inflation(
        &mut self,
        current_epoch: Epoch,
        events: &mut impl EmitEvents,
    ) -> Result<()> {
        let last_epoch = current_epoch
            .prev()
            .expect("Must have a prev epoch when applying inflation");

        // Get the number of blocks in the last epoch
        let first_block_of_last_epoch =
            self.state.in_mem().block.pred_epochs.first_block_heights
                [usize::try_from(last_epoch.0)
                    .expect("Last epoch shouldn't exceed `usize::MAX`")]
            .0;
        let num_blocks_in_last_epoch = self
            .state
            .in_mem()
            .block
            .height
            .0
            .checked_sub(first_block_of_last_epoch)
            .expect(
                "First block of last epoch must always be lower than or equal \
                 to current block height",
            );

        // PoS inflation
        proof_of_stake::rewards::apply_inflation::<
            _,
            governance::Store<_>,
            parameters::Store<_>,
            token::Store<_>,
        >(&mut self.state, last_epoch, num_blocks_in_last_epoch)?;

        // Pgf inflation
        pgf_apply_inflation(self.state.restrict_writes_to_write_log())?;

        // Take events that may be emitted from PGF
        for event in self.state.write_log_mut().take_events() {
            events.emit(event.with(Height(
                self.state.in_mem().get_last_block_height().next_height(),
            )));
        }

        Ok(())
    }

    // Write the batch hash to storage and mark the corresponding wrapper
    // hash as redundant (we check the batch hash too when validating
    // the wrapper). Requires the wrapper transaction as argument to recover
    // both the hashes.
    fn commit_batch_hash(&mut self, hashes: Option<ReplayProtectionHashes>) {
        if let Some(ReplayProtectionHashes {
            raw_header_hash,
            header_hash,
        }) = hashes
        {
            self.state
                .write_tx_hash(raw_header_hash)
                .expect("Error while writing tx hash to storage");

            self.state
                .redundant_tx_hash(&header_hash)
                .expect("Error while marking tx hash as redundant");
        }
    }

    // Evaluate the result of a transaction. Commit or drop the storage changes,
    // update stats and event, manage replay protection. For successful wrapper
    // transactions return the relevant data and delay the evaluation after the
    // batch execution
    fn evaluate_tx_result(
        &mut self,
        response: &mut shim::response::FinalizeBlock,
        extended_dispatch_result: std::result::Result<
            namada_sdk::tx::data::TxResult<protocol::Error>,
            Box<DispatchError>,
        >,
        tx_data: TxData<'_>,
        mut tx_logs: TxLogs<'_>,
    ) -> Option<WrapperCache> {
        match extended_dispatch_result {
            Ok(mut tx_result) => match tx_data.tx.header.tx_type {
                TxType::Wrapper(_) => {
                    // Commit any changes brought in by the inner txs executed
                    // when handling the wrapper. For now it should be at most
                    // one, the first tx of the batch that runs to pay fees via
                    // the masp, this way we can commit the fee payment itself
                    self.state.write_log_mut().commit_batch_and_current_tx();

                    // Emit the events of all the inner txs that have been
                    // successfully executed when handling the wrapper. These
                    // txs have just been committed so we need to ensure the
                    // relative events are emitted for consistency
                    for cmt in tx_data.tx.commitments() {
                        let inner_tx_hash = compute_inner_tx_hash(
                            tx_data.tx.wrapper_hash().as_ref(),
                            Either::Right(cmt),
                        );
                        if let Some(Ok(batched_result)) =
                            tx_result.get_mut(&inner_tx_hash)
                        {
                            if batched_result.is_accepted() {
                                // Take the events from the batch result to
                                // avoid emitting them again after the exection
                                // of the entire batch
                                response.events.emit_many(
                                    std::mem::take(&mut batched_result.events)
                                        .into_iter()
                                        .map(|event| {
                                            event.with(Height(tx_data.height))
                                        }),
                                );
                            }
                        }
                    }

                    // Return cached data for the execution of the batch
                    return Some(WrapperCache {
                        tx: tx_data.tx.to_owned(),
                        tx_index: tx_data.tx_index,
                        gas_meter: tx_data.tx_gas_meter,
                        event: tx_logs.tx_event,
                        tx_result,
                    });
                }
                _ => self.handle_inner_tx_results(
                    response,
                    tx_result,
                    tx_data,
                    &mut tx_logs,
                ),
            },
            Err(dispatch_error) => match *dispatch_error {
                DispatchError {
                    error: protocol::Error::WrapperRunnerError(msg),
                    tx_result: _,
                } => {
                    tracing::info!(
                        "Wrapper transaction {} failed with: {}",
                        tx_logs
                            .tx_event
                            .raw_read_attribute::<TxHash>()
                            .unwrap_or("<unknown>"),
                        msg,
                    );
                    let gas_scale = tx_data.tx_gas_meter.get_gas_scale();
                    let scaled_gas = tx_data
                        .tx_gas_meter
                        .get_consumed_gas()
                        .get_whole_gas_units(gas_scale);
                    tx_logs
                        .tx_event
                        .extend(GasUsed(scaled_gas))
                        .extend(Info(msg.to_string()))
                        .extend(Code(ResultCode::InvalidTx));
                    // Drop the batch write log which could contain invalid
                    // data. Important data that could be
                    // valid (e.g. a valid fee payment) must
                    // have already been moved to the block write log by now
                    self.state.write_log_mut().drop_batch();
                }
                _ => {
                    // This branch represents an error that affects the entire
                    // batch
                    let (msg, tx_result) = (
                        Error::TxApply(dispatch_error.error),
                        // The tx result should always be present at this point
                        dispatch_error.tx_result.unwrap_or_default(),
                    );
                    tracing::info!(
                        "Transaction {} failed with: {}",
                        tx_logs
                            .tx_event
                            .raw_read_attribute::<TxHash>()
                            .unwrap_or("<unknown>"),
                        msg
                    );

                    let gas_scale = tx_data.tx_gas_meter.get_gas_scale();
                    let scaled_gas = tx_data
                        .tx_gas_meter
                        .get_consumed_gas()
                        .get_whole_gas_units(gas_scale);

                    tx_logs
                        .tx_event
                        .extend(GasUsed(scaled_gas))
                        .extend(Info(msg.to_string()))
                        .extend(Code(ResultCode::WasmRuntimeError));

                    self.handle_batch_error(
                        response,
                        &msg,
                        tx_result,
                        tx_data,
                        &mut tx_logs,
                    );
                }
            },
        }

        response.events.emit(tx_logs.tx_event);
        None
    }

    // Evaluate the results of all the transactions of the batch. Commit or drop
    // the storage changes, update stats and event, manage replay protection.
    fn handle_inner_tx_results(
        &mut self,
        response: &mut shim::response::FinalizeBlock,
        mut tx_result: namada_sdk::tx::data::TxResult<protocol::Error>,
        tx_data: TxData<'_>,
        tx_logs: &mut TxLogs<'_>,
    ) {
        let mut temp_log = TempTxLogs::new_from_tx_logs(tx_logs);

        let ValidityFlags {
            commit_batch_hash,
            is_any_tx_invalid,
        } = temp_log.check_inner_results(&mut tx_result, tx_data.height);

        if tx_data.is_atomic_batch && is_any_tx_invalid {
            // Atomic batches need custom handling when even a single tx fails,
            // since we need to drop everything
            let unrun_txs = tx_data
                .commitments_len
                .checked_sub(
                    u64::try_from(tx_result.len())
                        .expect("Should be able to convert to u64"),
                )
                .expect("Shouldn't underflow");
            temp_log.stats.set_failing_atomic_batch(unrun_txs);
            temp_log.commit_stats_only(tx_logs);
            self.state.write_log_mut().drop_batch();
            tx_logs.tx_event.extend(Code(ResultCode::WasmRuntimeError));
        } else {
            self.state.write_log_mut().commit_batch_and_current_tx();
            self.state
                .in_mem_mut()
                .block
                .results
                .accept(tx_data.tx_index);
            temp_log.commit(tx_logs, response);

            // Atomic successful batches or non-atomic batches (even if the
            // inner txs failed) are marked as Ok
            tx_logs.tx_event.extend(Code(ResultCode::Ok));
        }

        if commit_batch_hash {
            // If at least one of the inner txs of the batch requires its hash
            // to be committed than commit the hash of the entire batch
            self.commit_batch_hash(tx_data.replay_protection_hashes);
        }

        let gas_scale = tx_data.tx_gas_meter.get_gas_scale();
        let scaled_gas = tx_data
            .tx_gas_meter
            .get_consumed_gas()
            .get_whole_gas_units(gas_scale);

        tx_logs
            .tx_event
            .extend(GasUsed(scaled_gas))
            .extend(Info("Check batch for result.".to_string()))
            .extend(Batch(&tx_result.to_result_string()));
    }

    fn handle_batch_error(
        &mut self,
        response: &mut shim::response::FinalizeBlock,
        msg: &Error,
        mut tx_result: namada_sdk::tx::data::TxResult<protocol::Error>,
        tx_data: TxData<'_>,
        tx_logs: &mut TxLogs<'_>,
    ) {
        let mut temp_log = TempTxLogs::new_from_tx_logs(tx_logs);

        let ValidityFlags {
            commit_batch_hash,
            is_any_tx_invalid: _,
        } = temp_log.check_inner_results(&mut tx_result, tx_data.height);

        let unrun_txs = tx_data
            .commitments_len
            .checked_sub(
                u64::try_from(tx_result.len())
                    .expect("Should be able to convert to u64"),
            )
            .expect("Shouldn't underflow");

        if tx_data.is_atomic_batch {
            tx_logs.stats.set_failing_atomic_batch(unrun_txs);
            temp_log.commit_stats_only(tx_logs);
            self.state.write_log_mut().drop_batch();
        } else {
            temp_log.stats.set_failing_batch(unrun_txs);
            self.state
                .in_mem_mut()
                .block
                .results
                .accept(tx_data.tx_index);
            temp_log.commit(tx_logs, response);
            // Commit the successful inner transactions before the error. Drop
            // the current tx write log which might be still populated with data
            // to be discarded (this is the case when we propagate an error
            // from the function that runs the actual batch)
            self.state.write_log_mut().drop_tx();
            self.state.write_log_mut().commit_batch_only();
        }

        if commit_batch_hash {
            // If at least one of the inner txs of the batch requires its hash
            // to be committed than commit the hash of the entire batch
            // regardless of the specific error
            self.commit_batch_hash(tx_data.replay_protection_hashes);
        } else {
            self.handle_batch_error_reprot(msg, tx_data);
        }

        tx_logs
            .tx_event
            .extend(Batch(&tx_result.to_result_string()));
    }

    fn handle_batch_error_reprot(&mut self, err: &Error, tx_data: TxData<'_>) {
        // If user transaction didn't fail because of out of gas nor replay
        // attempt, commit its hash to prevent replays. If it failed because of
        // a replay attempt just remove the redundant wrapper hash
        if !matches!(
            err,
            Error::TxApply(protocol::Error::GasError(_))
                | Error::TxApply(protocol::Error::ReplayAttempt(_))
        ) {
            self.commit_batch_hash(tx_data.replay_protection_hashes);
        } else if let Error::TxApply(protocol::Error::ReplayAttempt(_)) = err {
            // Remove the wrapper hash but keep the inner tx
            // hash. A replay of the wrapper is impossible since
            // the inner tx hash is committed to storage and
            // we validate the wrapper against that hash too
            let header_hash = tx_data
                .replay_protection_hashes
                .expect("This cannot fail")
                .header_hash;
            self.state
                .redundant_tx_hash(&header_hash)
                .expect("Error while marking tx hash as redundant");
        }
    }

    // Get the transactions from the consensus engine, preprocess and execute
    // them. Return the cache of successful wrapper transactions later used when
    // executing the inner txs.
    fn retrieve_and_execute_transactions(
        &mut self,
        native_block_proposer_address: &Address,
        processed_txs: &[shim::request::ProcessedTx],
        gas_scale: u64,
        ExecutionArgs {
            response,
            changed_keys,
            stats,
            height,
        }: ExecutionArgs<'_>,
    ) -> Vec<WrapperCache> {
        let mut successful_wrappers = vec![];

        for (tx_index, processed_tx) in processed_txs.iter().enumerate() {
            let tx =
                if let Ok(tx) = Tx::try_from_bytes(processed_tx.tx.as_ref()) {
                    tx
                } else {
                    tracing::error!(
                        "FinalizeBlock received a tx that could not be \
                         deserialized to a Tx type. This is likely a protocol \
                         transaction."
                    );
                    continue;
                };

            let result_code = ResultCode::from_u32(processed_tx.result.code)
                .expect("Result code conversion should not fail");

            let tx_header = tx.header();
            // If [`process_proposal`] rejected a Tx, emit an event here and
            // move on to next tx
            if result_code != ResultCode::Ok {
                let base_event: Event = match result_code {
                    // If [`process_proposal`] rejected a Tx due to invalid
                    // signature, emit an event here and
                    // move on to next tx
                    ResultCode::InvalidSig => match tx.header().tx_type {
                        TxType::Wrapper(_) | TxType::Protocol(_) => {
                            new_tx_event(&tx, height.0)
                        }
                        _ => {
                            tracing::error!(
                                "Internal logic error: FinalizeBlock received \
                                 a tx with an invalid signature error code \
                                 that could not be deserialized to a \
                                 WrapperTx / ProtocolTx type"
                            );
                            continue;
                        }
                    },
                    _ => new_tx_event(&tx, height.0),
                };
                response.events.emit(
                    base_event
                        .with(Code(result_code))
                        .with(Info(format!(
                            "Tx rejected: {}",
                            &processed_tx.result.info
                        )))
                        .with(GasUsed(0.into())),
                );

                continue;
            }

            let (dispatch_args, tx_gas_meter): (
                DispatchArgs<'_, WasmCacheRwAccess>,
                TxGasMeter,
            ) = match &tx_header.tx_type {
                TxType::Wrapper(wrapper) => {
                    stats.increment_wrapper_txs();

                    let gas_limit =
                        match wrapper.gas_limit.as_scaled_gas(gas_scale) {
                            Ok(value) => value,
                            Err(_) => {
                                response.events.emit(
                                    new_tx_event(&tx, height.0)
                                        .with(Code(ResultCode::InvalidTx))
                                        .with(Info(
                                            "The wrapper gas limit overflowed \
                                             gas representation"
                                                .to_owned(),
                                        ))
                                        .with(GasUsed(0.into())),
                                );
                                continue;
                            }
                        };
                    let tx_gas_meter = TxGasMeter::new(gas_limit, gas_scale);
                    for cmt in tx.commitments() {
                        if let Some(code_sec) = tx
                            .get_section(cmt.code_sechash())
                            .and_then(|x| Section::code_sec(x.as_ref()))
                        {
                            stats.increment_tx_type(
                                code_sec.code.hash().to_string(),
                            );
                        }
                    }
                    (
                        DispatchArgs::Wrapper {
                            wrapper,
                            tx_bytes: processed_tx.tx.as_ref(),
                            tx_index: TxIndex::must_from_usize(tx_index),
                            height,
                            block_proposer: native_block_proposer_address,
                            vp_wasm_cache: &mut self.vp_wasm_cache,
                            tx_wasm_cache: &mut self.tx_wasm_cache,
                        },
                        tx_gas_meter,
                    )
                }
                TxType::Raw => {
                    tracing::error!(
                        "Internal logic error: FinalizeBlock received a \
                         TxType::Raw transaction"
                    );
                    continue;
                }
                TxType::Protocol(protocol_tx) => {
                    match protocol_tx.tx {
                        ProtocolTxType::BridgePoolVext
                        | ProtocolTxType::BridgePool
                        | ProtocolTxType::ValSetUpdateVext
                        | ProtocolTxType::ValidatorSetUpdate => (),

                        ProtocolTxType::EthEventsVext => {
                            let ext =
                        ethereum_tx_data_variants::EthEventsVext::try_from(&tx)
                            .unwrap();
                            if self
                                .mode
                                .get_validator_address()
                                .map(|validator| {
                                    validator == &ext.data.validator_addr
                                })
                                .unwrap_or(false)
                            {
                                for event in ext.data.ethereum_events.iter() {
                                    self.mode.dequeue_eth_event(event);
                                }
                            }
                        }
                        ProtocolTxType::EthereumEvents => {
                            let digest =
                        ethereum_tx_data_variants::EthereumEvents::try_from(
                            &tx,
                        )
                        .unwrap();
                            if let Some(address) =
                                self.mode.get_validator_address().cloned()
                            {
                                let this_signer = &(
                                    address,
                                    self.state.in_mem().get_last_block_height(),
                                );
                                for MultiSignedEthEvent { event, signers } in
                                    &digest.events
                                {
                                    if signers.contains(this_signer) {
                                        self.mode.dequeue_eth_event(event);
                                    }
                                }
                            }
                        }
                    }
                    (
                        DispatchArgs::Protocol(protocol_tx),
                        TxGasMeter::new(0, gas_scale),
                    )
                }
            };
            let tx_event = new_tx_event(&tx, height.0);
            let is_atomic_batch = tx.header.atomic;
            let commitments_len = tx.commitments().len() as u64;
            let tx_hash = tx.header_hash();
            let tx_gas_meter = RefCell::new(tx_gas_meter);

            let dispatch_result = protocol::dispatch_tx(
                &tx,
                dispatch_args,
                &tx_gas_meter,
                &mut self.state,
            );
            let tx_gas_meter = tx_gas_meter.into_inner();
            let consumed_gas = tx_gas_meter.get_consumed_gas();

            // save the gas cost
            self.update_tx_gas(tx_hash, consumed_gas);

            if let Some(wrapper_cache) = self.evaluate_tx_result(
                response,
                dispatch_result,
                TxData {
                    is_atomic_batch,
                    tx: &tx,
                    commitments_len,
                    tx_index,
                    replay_protection_hashes: None,
                    tx_gas_meter,
                    height,
                },
                TxLogs {
                    tx_event,
                    stats,
                    changed_keys,
                },
            ) {
                successful_wrappers.push(wrapper_cache);
            }
        }

        successful_wrappers
    }

    // Execute the transaction batches for successful wrapper transactions
    fn execute_tx_batches(
        &mut self,
        successful_wrappers: Vec<WrapperCache>,
        ExecutionArgs {
            response,
            changed_keys,
            stats,
            height,
        }: ExecutionArgs<'_>,
    ) {
        for WrapperCache {
            mut tx,
            tx_index,
            gas_meter: tx_gas_meter,
            event: tx_event,
            tx_result: wrapper_tx_result,
        } in successful_wrappers
        {
            let tx_hash = tx.header_hash();
            let is_atomic_batch = tx.header.atomic;
            let commitments_len = tx.commitments().len() as u64;
            let replay_protection_hashes = Some(ReplayProtectionHashes {
                raw_header_hash: tx.raw_header_hash(),
                header_hash: tx.header_hash(),
            });

            // change tx type to raw for execution
            tx.update_header(TxType::Raw);
            let tx_gas_meter = RefCell::new(tx_gas_meter);
            let dispatch_result = protocol::dispatch_tx(
                &tx,
                DispatchArgs::Raw {
                    wrapper_hash: Some(&tx_hash),
                    tx_index: TxIndex::must_from_usize(tx_index),
                    height,
                    wrapper_tx_result: Some(wrapper_tx_result),
                    vp_wasm_cache: &mut self.vp_wasm_cache,
                    tx_wasm_cache: &mut self.tx_wasm_cache,
                },
                &tx_gas_meter,
                &mut self.state,
            );
            let tx_gas_meter = tx_gas_meter.into_inner();
            let consumed_gas = tx_gas_meter.get_consumed_gas();

            // update the gas cost of the corresponding wrapper
            self.update_tx_gas(tx_hash, consumed_gas);

            self.evaluate_tx_result(
                response,
                dispatch_result,
                TxData {
                    is_atomic_batch,
                    tx: &tx,
                    commitments_len,
                    tx_index,
                    replay_protection_hashes,
                    tx_gas_meter,
                    height,
                },
                TxLogs {
                    tx_event,
                    stats,
                    changed_keys,
                },
            );
        }
    }
}

struct ExecutionArgs<'finalize> {
    response: &'finalize mut shim::response::FinalizeBlock,
    changed_keys: &'finalize mut BTreeSet<Key>,
    stats: &'finalize mut InternalStats,
    height: BlockHeight,
}

// Caches the execution of a wrapper transaction to be used when later executing
// the inner batch
struct WrapperCache {
    tx: Tx,
    tx_index: usize,
    gas_meter: TxGasMeter,
    event: Event,
    tx_result: namada_sdk::tx::data::TxResult<protocol::Error>,
}

struct TxData<'tx> {
    is_atomic_batch: bool,
    tx: &'tx Tx,
    commitments_len: u64,
    tx_index: usize,
    replay_protection_hashes: Option<ReplayProtectionHashes>,
    tx_gas_meter: TxGasMeter,
    height: BlockHeight,
}

struct TxLogs<'finalize> {
    tx_event: Event,
    stats: &'finalize mut InternalStats,
    changed_keys: &'finalize mut BTreeSet<Key>,
}

#[derive(Default)]
struct ValidityFlags {
    // Track the need to commit the batch hash for replay protection. Hash
    // must be written if at least one of the txs in the batch requires so
    commit_batch_hash: bool,
    // Track if any of the inner txs failed or was rejected
    is_any_tx_invalid: bool,
}

// Temporary support type to update the tx logs. If the tx is confirmed this
// gets merged to the non-temporary type
struct TempTxLogs {
    tx_event: Event,
    stats: InternalStats,
    changed_keys: BTreeSet<Key>,
    response_events: Vec<Event>,
}

impl TempTxLogs {
    fn new_from_tx_logs(tx_logs: &TxLogs<'_>) -> Self {
        Self {
            tx_event: Event::new(
                tx_logs.tx_event.kind().to_owned(),
                tx_logs.tx_event.level().to_owned(),
            ),
            stats: Default::default(),
            changed_keys: Default::default(),
            response_events: Default::default(),
        }
    }
}

impl<'finalize> TempTxLogs {
    // Consumes the temporary logs and merges them to confirmed ones. Pushes ibc
    // and eth events to the finalize block response
    fn commit(
        self,
        logs: &mut TxLogs<'finalize>,
        response: &mut shim::response::FinalizeBlock,
    ) {
        logs.tx_event.merge(self.tx_event);
        logs.stats.merge(self.stats);
        logs.changed_keys.extend(self.changed_keys);
        response.events.extend(self.response_events);
    }

    // Consumes the temporary logs and merges the statistics to confirmed ones.
    // This is useful for failing atomic batches
    fn commit_stats_only(self, logs: &mut TxLogs<'finalize>) {
        logs.stats.merge(self.stats);
    }

    fn check_inner_results(
        &mut self,
        tx_result: &mut namada_sdk::tx::data::TxResult<protocol::Error>,
        height: BlockHeight,
    ) -> ValidityFlags {
        let mut flags = ValidityFlags::default();

        for (cmt_hash, batched_result) in tx_result.iter_mut() {
            match batched_result {
                Ok(result) => {
                    if result.is_accepted() {
                        tracing::trace!(
                            "all VPs accepted inner tx {} storage \
                             modification {:#?}",
                            cmt_hash,
                            result
                        );

                        self.changed_keys
                            .extend(result.changed_keys.iter().cloned());
                        self.stats.increment_successful_txs();
                        flags.commit_batch_hash = true;

                        self.response_events.emit_many(
                            // Take the events to avoid replicating them when
                            // emitting the transaction's result event
                            std::mem::take(&mut result.events)
                                .into_iter()
                                .map(|event| event.with(Height(height))),
                        );
                    } else {
                        // VPs rejected, this branch can only be reached by
                        // inner txs
                        tracing::trace!(
                            "some VPs rejected inner tx {} storage \
                             modification {:#?}",
                            cmt_hash,
                            result.vps_result.rejected_vps
                        );

                        // If an inner tx failed for any reason but invalid
                        // signature, commit its hash to storage, otherwise
                        // allow for a replay
                        if !result
                            .vps_result
                            .status_flags
                            .contains(VpStatusFlags::INVALID_SIGNATURE)
                        {
                            flags.commit_batch_hash = true;
                        }

                        self.stats.increment_rejected_txs();
                        flags.is_any_tx_invalid = true;
                    }
                }
                Err(e) => {
                    tracing::trace!("Inner tx {} failed: {}", cmt_hash, e);
                    // If inner transaction didn't fail because of invalid
                    // section commitment, commit its hash to prevent replays
                    if !matches!(e, protocol::Error::MissingSection(_)) {
                        flags.commit_batch_hash = true;
                    }

                    self.stats.increment_errored_txs();
                    flags.is_any_tx_invalid = true;
                }
            }
        }

        flags
    }
}

struct ReplayProtectionHashes {
    raw_header_hash: Hash,
    header_hash: Hash,
}

/// Convert ABCI vote info to PoS vote info. Any info which fails the conversion
/// will be skipped and errors logged.
///
/// # Panics
/// Panics if a validator's address cannot be converted to native address
/// (either due to storage read error or the address not being found) or
/// if the voting power cannot be converted to u64.
fn pos_votes_from_abci(
    storage: &impl StorageRead,
    votes: &[VoteInfo],
) -> Vec<proof_of_stake::types::VoteInfo> {
    votes
        .iter()
        .filter_map(
            |VoteInfo {
                 validator,
                 sig_info,
             }| {
                let crate::tendermint::abci::types::Validator {
                    address,
                    power,
                } = validator;
                let tm_raw_hash_string = HEXUPPER.encode(address);
                if sig_info.is_signed() {
                    tracing::debug!(
                        "Looking up validator from Tendermint VoteInfo's raw \
                         hash {tm_raw_hash_string}"
                    );

                    // Look-up the native address
                    let validator_address = find_validator_by_raw_hash(
                        storage,
                        &tm_raw_hash_string,
                    )
                    .expect(
                        "Must be able to read from storage to find native \
                         address of validator from tendermint raw hash",
                    )
                    .expect(
                        "Must be able to find the native address of validator \
                         from tendermint raw hash",
                    );

                    // Try to convert voting power to u64
                    let validator_vp = u64::from(*power);

                    Some(proof_of_stake::types::VoteInfo {
                        validator_address,
                        validator_vp,
                    })
                } else {
                    tracing::debug!(
                        "Validator {tm_raw_hash_string} didn't sign last block"
                    );
                    None
                }
            },
        )
        .collect()
}

/// Dependency-injection indirection for governance system
fn gov_finalize_block<D, H>(
    shell: &mut Shell<D, H>,
    emit_events: &mut Vec<Event>,
    current_epoch: Epoch,
    is_new_epoch: bool,
    gas_scale: u64,
) -> Result<()>
where
    D: DB + for<'iter> DBIter<'iter> + Sync,
    H: StorageHasher + Sync,
{
    let vp_wasm_cache = &mut shell.vp_wasm_cache;
    let tx_wasm_cache = &mut shell.tx_wasm_cache;
    let height = shell.state.get_block_height()?;
    governance::finalize_block::<
        _,
        token::Store<_>,
        proof_of_stake::Store<_>,
        _,
        _,
    >(
        &mut shell.state,
        emit_events,
        current_epoch,
        is_new_epoch,
        |tx, state| {
            let dispatch_result = protocol::dispatch_tx(
                tx,
                protocol::DispatchArgs::Raw {
                    wrapper_hash: None,
                    tx_index: TxIndex::default(),
                    height,
                    wrapper_tx_result: None,
                    vp_wasm_cache,
                    tx_wasm_cache,
                },
                // No gas limit for governance proposal
                &RefCell::new(TxGasMeter::new(u64::MAX, gas_scale)),
                state,
            );
            // Governance must construct the tx with data and code commitments
            let cmt = tx.first_commitments().unwrap().to_owned();
            match dispatch_result {
                Ok(tx_result) => match tx_result
                    .get_inner_tx_result(None, either::Right(&cmt))
                    .expect("Proposal tx must have a result")
                {
                    Ok(batched_result) => {
                        if batched_result.is_accepted() {
                            state.write_log_mut().commit_batch_and_current_tx();
                            Ok(true)
                        } else {
                            tracing::warn!(
                                "Governance proposal rejected by VP(s): {}",
                                batched_result.vps_result
                            );
                            state.write_log_mut().drop_batch();
                            Ok(false)
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Error executing governance proposal {e}",
                        );
                        state.write_log_mut().drop_batch();
                        Ok(false)
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        "Error executing governance proposal {}",
                        e.error
                    );
                    state.write_log_mut().drop_batch();
                    Ok(false)
                }
            }
        },
        |state, token, source, target| {
            ibc::transfer_over_ibc::<
                _,
                parameters::Store<_>,
                token::Store<_>,
                token::Transfer,
            >(state, token, source, target)
        },
    )
}

/// Dependency-injection indirection for token system
fn token_finalize_block<S>(
    storage: &mut S,
    events: &mut Vec<Event>,
    is_new_masp_epoch: bool,
) -> Result<()>
where
    S: StorageWrite + StorageRead + token::WithConversionState,
{
    token::finalize_block::<S, parameters::Store<_>>(
        storage,
        events,
        is_new_masp_epoch,
    )
}

/// Dependency-injection indirection for PoS system
fn pos_finalize_block<S>(
    storage: &mut S,
    events: &mut impl EmitEvents,
    is_new_epoch: bool,
    validator_set_update_epoch: Epoch,
    votes: Vec<proof_of_stake::types::VoteInfo>,
    byzantine_validators: Vec<Misbehavior>,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    proof_of_stake::finalize_block::<_, governance::Store<_>>(
        storage,
        events,
        is_new_epoch,
        validator_set_update_epoch,
        votes,
        byzantine_validators,
    )
}

/// Dependency-injection indirection for PGF inflation
fn pgf_apply_inflation<S>(storage: &mut S) -> Result<()>
where
    S: 'static + State + EmitEvents,
{
    pgf_inflation::apply_inflation::<_, parameters::Store<_>, token::Store<_>, _>(
        storage,
        |state, token, source, target| {
            ibc::transfer_over_ibc::<
                _,
                parameters::Store<_>,
                token::Store<_>,
                token::Transfer,
            >(state, token, source, target)
        },
    )
}

/// We test the failure cases of [`finalize_block`]. The happy flows
/// are covered by the e2e tests.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
#[cfg(test)]
mod test_finalize_block {
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;
    use std::str::FromStr;

    use namada_apps_lib::wallet::defaults::albert_keypair;
    use namada_replay_protection as replay_protection;
    use namada_sdk::address;
    use namada_sdk::collections::{HashMap, HashSet};
    use namada_sdk::dec::{Dec, POS_DECIMAL_PRECISION};
    use namada_sdk::eth_bridge::MinimumConfirmations;
    use namada_sdk::eth_bridge::storage::bridge_pool::{
        self, get_key_from_hash, get_nonce_key, get_signed_root_key,
    };
    use namada_sdk::eth_bridge::storage::eth_bridge_queries::is_bridge_comptime_enabled;
    use namada_sdk::eth_bridge::storage::vote_tallies::BridgePoolRoot;
    use namada_sdk::eth_bridge::storage::{
        min_confirmations_key, wrapped_erc20s,
    };
    use namada_sdk::ethereum_events::{EthAddress, Uint as ethUint};
    use namada_sdk::events::Event;
    use namada_sdk::events::extend::Log;
    use namada_sdk::gas::{GasMeterKind, VpGasMeter};
    use namada_sdk::governance::storage::keys::get_proposal_execution_key;
    use namada_sdk::governance::storage::proposal::ProposalType;
    use namada_sdk::governance::{
        InitProposalData, ProposalVote, VoteProposalData,
    };
    use namada_sdk::hash::Hash;
    use namada_sdk::keccak::KeccakHash;
    use namada_sdk::key::testing::common_sk_from_simple_seed;
    use namada_sdk::parameters::EpochDuration;
    use namada_sdk::proof_of_stake::storage::{
        enqueued_slashes_handle, get_num_consensus_validators,
        liveness_missed_votes_handle, liveness_sum_missed_votes_handle,
        read_consensus_validator_set_addresses,
        read_consensus_validator_set_addresses_with_stake, read_total_stake,
        read_validator_stake, rewards_accumulator_handle,
        validator_consensus_key_handle, validator_rewards_products_handle,
        validator_slashes_handle, validator_state_handle, write_pos_params,
    };
    use namada_sdk::proof_of_stake::storage_key::{
        is_validator_slashes_key, slashes_prefix,
    };
    use namada_sdk::proof_of_stake::types::{
        BondId, SlashType, ValidatorState, WeightedValidator,
    };
    use namada_sdk::proof_of_stake::{
        ADDRESS as pos_address, unjail_validator,
    };
    use namada_sdk::storage::KeySeg;
    use namada_sdk::tendermint::abci::types::{Misbehavior, MisbehaviorKind};
    use namada_sdk::time::DurationSecs;
    use namada_sdk::token::{
        Amount, DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES, read_balance,
        read_denom, update_balance,
    };
    use namada_sdk::tx::data::Fee;
    use namada_sdk::tx::event::Code as CodeAttr;
    use namada_sdk::tx::event::types::APPLIED as APPLIED_TX;
    use namada_sdk::tx::{Authorization, Code, Data};
    use namada_sdk::uint::Uint;
    use namada_sdk::validation::ParametersVp;
    use namada_test_utils::TestWasms;
    use namada_test_utils::tx_data::TxWriteData;
    use namada_vm::wasm::run::VpEvalWasm;
    use namada_vote_ext::ethereum_events;
    use proof_of_stake::{PosParams, bond_tokens};
    use test_log::test;

    use super::*;
    use crate::oracle::control::Command;
    use crate::shell::test_utils::*;
    use crate::shims::abcipp_shim_types::shim::request::{
        FinalizeBlock, ProcessedTx,
    };
    use crate::tendermint::abci::types::Validator;

    const WRAPPER_GAS_LIMIT: u64 = 10_000_000;
    const STORAGE_VALUE: &str = "test_value";

    /// Make a wrapper tx and a processed tx from the wrapped tx that can be
    /// added to `FinalizeBlock` request.
    fn mk_wrapper_tx(
        shell: &TestShell,
        keypair: &common::SecretKey,
    ) -> (Tx, ProcessedTx) {
        let tx_code = TestWasms::TxNoOp.read_bytes();
        let mut wrapper_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                WRAPPER_GAS_LIMIT.into(),
            ))));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.set_code(Code::new(tx_code, None));
        wrapper_tx.add_section(Section::Authorization(Authorization::new(
            wrapper_tx.sechashes(),
            [(0, keypair.clone())].into_iter().collect(),
            None,
        )));
        let tx = wrapper_tx.to_bytes();
        (
            wrapper_tx,
            ProcessedTx {
                tx: tx.into(),
                result: TxResult {
                    code: ResultCode::Ok.into(),
                    info: "".into(),
                },
            },
        )
    }

    // Make a transaction batch with three transactions. Optionally make the
    // batch atomic, request the failure or out of gas of the second transaction
    fn mk_tx_batch(
        shell: &TestShell,
        sk: &common::SecretKey,
        set_atomic: bool,
        should_fail: bool,
        should_run_out_of_gas: bool,
    ) -> (Tx, ProcessedTx) {
        let mut batch =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                sk.ref_to(),
                WRAPPER_GAS_LIMIT.into(),
            ))));
        batch.header.chain_id = shell.chain_id.clone();
        batch.header.atomic = set_atomic;

        // append first inner tx to batch
        let data = TxWriteData {
            key: "random_key_1".parse().unwrap(),
            value: STORAGE_VALUE.serialize_to_vec(),
        };
        batch.set_data(Data::new(data.serialize_to_vec()));
        batch.set_code(Code::new(
            TestWasms::TxWriteStorageKey.read_bytes(),
            None,
        ));

        // append second inner tx to batch
        batch.push_default_inner_tx();
        let tx_code = if should_fail {
            TestWasms::TxFail.read_bytes()
        } else if should_run_out_of_gas {
            TestWasms::TxInfiniteHostGas.read_bytes()
        } else {
            TestWasms::TxWriteStorageKey.read_bytes()
        };
        let data = TxWriteData {
            key: "random_key_2".parse().unwrap(),
            value: STORAGE_VALUE.serialize_to_vec(),
        };
        batch.set_data(Data::new(data.serialize_to_vec()));
        batch.set_code(Code::new(tx_code, None));

        // append last inner tx to batch
        batch.push_default_inner_tx();
        let data = TxWriteData {
            key: "random_key_3".parse().unwrap(),
            value: STORAGE_VALUE.serialize_to_vec(),
        };
        batch.set_data(Data::new(data.serialize_to_vec()));
        batch.set_code(Code::new(
            TestWasms::TxWriteStorageKey.read_bytes(),
            None,
        ));

        batch.add_section(Section::Authorization(Authorization::new(
            vec![batch.raw_header_hash()],
            [(0, sk.clone())].into_iter().collect(),
            None,
        )));
        batch.add_section(Section::Authorization(Authorization::new(
            batch.sechashes(),
            [(0, sk.clone())].into_iter().collect(),
            None,
        )));
        let tx = batch.to_bytes();
        (
            batch,
            ProcessedTx {
                tx: tx.into(),
                result: TxResult {
                    code: ResultCode::Ok.into(),
                    info: "".into(),
                },
            },
        )
    }

    /// Check that if a wrapper tx was rejected by [`process_proposal`], the
    /// correct event is returned.
    #[test]
    fn test_process_proposal_rejected_wrapper_tx() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();
        let mut processed_txs = vec![];

        // Add unshielded balance for fee payment
        let native_token = shell.state.in_mem().native_token.clone();
        update_balance(
            &mut shell.state,
            &native_token,
            &Address::from(&keypair.ref_to()),
            |_| Ok(Amount::native_whole(1000)),
        )
        .unwrap();

        // Need ordered tx hashes because the events can be emitted out of order
        let mut ordered_hashes = vec![];
        // create some wrapper txs
        for i in 0u64..4 {
            let (tx, mut processed_tx) = mk_wrapper_tx(&shell, &keypair);
            processed_tx.result.code = u32::try_from(i.rem_euclid(2)).unwrap();
            processed_txs.push(processed_tx);
            ordered_hashes.push(tx.header_hash());
        }

        // check that the correct events were created
        for event in shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs.clone(),
                ..Default::default()
            })
            .expect("Test failed")
            .iter()
        {
            assert_eq!(*event.kind(), APPLIED_TX);
            let hash = event.read_attribute::<TxHash>().expect("Test failed");
            let index = ordered_hashes
                .iter()
                .enumerate()
                .find_map(
                    |(idx, tx_hash)| {
                        if tx_hash == &hash { Some(idx) } else { None }
                    },
                )
                .unwrap();
            let code = event
                .read_attribute::<CodeAttr>()
                .expect("Test failed")
                .to_usize();
            assert_eq!(code, index.rem_euclid(2));
        }
    }

    /// Test if a rejected protocol tx is applied and emits
    /// the correct event
    #[test]
    fn test_rejected_protocol_tx() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);
        let (mut shell, _, _, _) = setup_at_height(LAST_HEIGHT);
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();

        let tx = EthereumTxData::EthereumEvents(ethereum_events::VextDigest {
            signatures: Default::default(),
            events: vec![],
        })
        .sign(&protocol_key, shell.chain_id.clone())
        .to_bytes();

        let req = FinalizeBlock {
            txs: vec![ProcessedTx {
                tx: tx.into(),
                result: TxResult {
                    code: ResultCode::InvalidTx.into(),
                    info: Default::default(),
                },
            }],
            ..Default::default()
        };
        let mut resp = shell.finalize_block(req).expect("Test failed");
        assert_eq!(resp.len(), 1);
        let event = resp.remove(0);
        assert_eq!(*event.kind(), APPLIED_TX);
        let code = event.read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::InvalidTx);
    }

    /// Test that once a validator's vote for an Ethereum event lands
    /// on-chain from a vote extension digest, it dequeues from the
    /// list of events to vote on.
    #[test]
    fn test_eth_events_dequeued_digest() {
        let (mut shell, _, oracle, _) = setup_at_height(3);
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();

        // ---- the ledger receives a new Ethereum event
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        tokio_test::block_on(oracle.send(event.clone())).expect("Test failed");
        let [queued_event]: [EthereumEvent; 1] =
            shell.new_ethereum_events().try_into().expect("Test failed");
        assert_eq!(queued_event, event);

        // ---- The protocol tx that includes this event on-chain
        let ext = ethereum_events::Vext {
            block_height: shell.state.in_mem().get_last_block_height(),
            ethereum_events: vec![event.clone()],
            validator_addr: address.clone(),
        }
        .sign(&protocol_key);

        let processed_tx = {
            let signed = MultiSignedEthEvent {
                event,
                signers: BTreeSet::from([(
                    address.clone(),
                    shell.state.in_mem().get_last_block_height(),
                )]),
            };

            let digest = ethereum_events::VextDigest {
                signatures: vec![(
                    (address, shell.state.in_mem().get_last_block_height()),
                    ext.sig,
                )]
                .into_iter()
                .collect(),
                events: vec![signed],
            };
            ProcessedTx {
                tx: EthereumTxData::EthereumEvents(digest)
                    .sign(&protocol_key, shell.chain_id.clone())
                    .to_bytes()
                    .into(),
                result: TxResult {
                    code: ResultCode::Ok.into(),
                    info: "".into(),
                },
            }
        };

        // ---- This protocol tx is accepted
        let [result]: [Event; 1] = shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
        assert_eq!(*result.kind(), APPLIED_TX);
        let code = result.read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);

        // --- The event is removed from the queue
        assert!(shell.new_ethereum_events().is_empty());
    }

    /// Test that once a validator's vote for an Ethereum event lands
    /// on-chain from a protocol tx, it dequeues from the
    /// list of events to vote on.
    #[test]
    fn test_eth_events_dequeued_protocol_tx() {
        let (mut shell, _, oracle, _) = setup_at_height(3);
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();

        // ---- the ledger receives a new Ethereum event
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        tokio_test::block_on(oracle.send(event.clone())).expect("Test failed");
        let [queued_event]: [EthereumEvent; 1] =
            shell.new_ethereum_events().try_into().expect("Test failed");
        assert_eq!(queued_event, event);

        // ---- The protocol tx that includes this event on-chain
        let ext = ethereum_events::Vext {
            block_height: shell.state.in_mem().get_last_block_height(),
            ethereum_events: vec![event],
            validator_addr: address,
        }
        .sign(&protocol_key);
        let processed_tx = ProcessedTx {
            tx: EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone())
                .to_bytes()
                .into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        };

        // ---- This protocol tx is accepted
        let [result]: [Event; 1] = shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
        assert_eq!(*result.kind(), APPLIED_TX);
        let code = result.read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);

        // --- The event is removed from the queue
        assert!(shell.new_ethereum_events().is_empty());
    }

    /// Actions to perform in [`test_bp`].
    enum TestBpAction {
        /// The tested unit correctly signed over the bridge pool root.
        VerifySignedRoot,
        /// The tested unit correctly incremented the bridge pool's nonce.
        CheckNonceIncremented,
    }

    /// Helper function for testing the relevant protocol tx
    /// for signing bridge pool roots and nonces
    fn test_bp<F>(craft_tx: F)
    where
        F: FnOnce(&mut TestShell) -> (Tx, TestBpAction),
    {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _, _, _) = setup_at_height(1u64);
        namada_sdk::eth_bridge::test_utils::commit_bridge_pool_root_at_height(
            &mut shell.state,
            &KeccakHash([1; 32]),
            1.into(),
        );
        let value = BlockHeight(2).serialize_to_vec();
        shell
            .state
            .in_mem_mut()
            .block
            .tree
            .update(&get_key_from_hash(&KeccakHash([1; 32])), value)
            .expect("Test failed");
        shell
            .state
            .db_write(&get_nonce_key(), Uint::from(1).serialize_to_vec())
            .expect("Test failed");
        let (tx, action) = craft_tx(&mut shell);
        let processed_tx = ProcessedTx {
            tx: tx.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        };
        let req = FinalizeBlock {
            txs: vec![processed_tx],
            ..Default::default()
        };
        let root = shell
            .state
            .read::<(BridgePoolRoot, BlockHeight)>(&get_signed_root_key())
            .expect("Reading signed Bridge pool root shouldn't fail.");
        assert!(root.is_none());
        _ = shell.finalize_block(req).expect("Test failed");
        shell.state.commit_block().unwrap();
        match action {
            TestBpAction::VerifySignedRoot => {
                let (root, _) = shell
                    .state
                    .ethbridge_queries()
                    .get_signed_bridge_pool_root()
                    .expect("Test failed");
                assert_eq!(root.data.0, KeccakHash([1; 32]));
                assert_eq!(root.data.1, ethUint::from(1));
            }
            TestBpAction::CheckNonceIncremented => {
                let nonce =
                    shell.state.ethbridge_queries().get_bridge_pool_nonce();
                assert_eq!(nonce, ethUint::from(2));
            }
        }
    }

    #[test]
    /// Test that adding a new erc20 transfer to the bridge pool
    /// increments the pool's nonce.
    fn test_bp_nonce_is_incremented() {
        test_bp(|shell: &mut TestShell| {
            let asset = EthAddress([0xff; 20]);
            let receiver = EthAddress([0xaa; 20]);
            let bertha = namada_apps_lib::wallet::defaults::bertha_address();
            // add bertha's escrowed `asset` to the pool
            {
                let token = wrapped_erc20s::token(&asset);
                let owner_key = token::storage_key::balance_key(
                    &token,
                    &bridge_pool::BRIDGE_POOL_ADDRESS,
                );
                let supply_key = token::storage_key::minted_balance_key(&token);
                let amt: Amount = 999_999_u64.into();
                shell.state.write(&owner_key, amt).expect("Test failed");
                shell.state.write(&supply_key, amt).expect("Test failed");
            }
            // add bertha's gas fees the pool
            {
                let amt: Amount = 999_999_u64.into();
                let native_token = shell.state.in_mem().native_token.clone();
                update_balance(
                    &mut shell.state,
                    &native_token,
                    &bridge_pool::BRIDGE_POOL_ADDRESS,
                    |_| Ok(amt),
                )
                .expect("Test failed");
            }
            // write transfer to storage
            let transfer = {
                use namada_sdk::eth_bridge_pool::{
                    GasFee, PendingTransfer, TransferToEthereum,
                    TransferToEthereumKind,
                };
                let pending = PendingTransfer {
                    transfer: TransferToEthereum {
                        kind: TransferToEthereumKind::Erc20,
                        amount: 10u64.into(),
                        asset,
                        recipient: receiver,
                        sender: bertha.clone(),
                    },
                    gas_fee: GasFee {
                        token: shell.state.in_mem().native_token.clone(),
                        amount: 10u64.into(),
                        payer: bertha.clone(),
                    },
                };
                let transfer = (&pending).into();
                shell
                    .state
                    .write(&bridge_pool::get_pending_key(&pending), pending)
                    .expect("Test failed");
                transfer
            };
            let ethereum_event = EthereumEvent::TransfersToEthereum {
                nonce: 1u64.into(),
                transfers: vec![transfer],
                relayer: bertha,
            };
            let (protocol_key, _) =
                namada_apps_lib::wallet::defaults::validator_keys();
            let validator_addr =
                namada_apps_lib::wallet::defaults::validator_address();
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr,
                    block_height: shell.state.in_mem().get_last_block_height(),
                    ethereum_events: vec![ethereum_event],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            let tx = EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone());
            (tx, TestBpAction::CheckNonceIncremented)
        });
    }

    #[test]
    /// Test that the generated protocol tx passes Finalize Block
    /// and effects the expected storage changes.
    fn test_bp_roots_protocol_tx() {
        test_bp(|shell: &mut TestShell| {
            let vext = shell.extend_vote_with_bp_roots().expect("Test failed");
            let tx = EthereumTxData::BridgePoolVext(vext.into()).sign(
                shell.mode.get_protocol_key().expect("Test failed"),
                shell.chain_id.clone(),
            );
            (tx, TestBpAction::VerifySignedRoot)
        });
    }

    /// Test the correct transition to a new masp epoch
    #[test]
    fn test_masp_epoch_progression() {
        let (mut shell, _broadcaster, _, _eth_control) = setup();

        let masp_epoch_multiplier =
            namada_sdk::parameters::read_masp_epoch_multiplier_parameter(
                &shell.state,
            )
            .unwrap();

        assert_eq!(shell.state.get_block_epoch().unwrap(), Epoch::default());

        for _ in 1..masp_epoch_multiplier {
            shell.start_new_epoch(None);
            assert!(
                !shell
                    .state
                    .is_masp_new_epoch(true, masp_epoch_multiplier)
                    .unwrap()
            );
        }
        shell.start_new_epoch(None);
        assert!(
            shell
                .state
                .is_masp_new_epoch(true, masp_epoch_multiplier)
                .unwrap()
        );
    }

    /// Test that the finalize block handler never commits changes directly to
    /// the DB.
    #[test]
    fn test_finalize_doesnt_commit_db() {
        let (mut shell, _broadcaster, _, _eth_control) = setup();

        // Update epoch duration to make sure we go through couple epochs
        let epoch_duration = EpochDuration {
            min_num_of_blocks: 5,
            min_duration: DurationSecs(0),
        };
        namada_sdk::parameters::update_epoch_parameter(
            &mut shell.state,
            &epoch_duration,
        )
        .unwrap();
        shell.state.in_mem_mut().next_epoch_min_start_height = BlockHeight(5);
        shell.state.in_mem_mut().next_epoch_min_start_time = {
            #[allow(clippy::disallowed_methods)]
            DateTimeUtc::now()
        };

        let txs_key = gen_keypair();
        // Add unshielded balance for fee payment
        let balance_key = token::storage_key::balance_key(
            &shell.state.in_mem().native_token,
            &Address::from(&txs_key.ref_to()),
        );
        shell
            .state
            .write(&balance_key, Amount::native_whole(1000))
            .unwrap();

        // Add a proposal to be executed on next epoch change.
        let mut add_proposal = |proposal_id, vote| {
            let validator = shell.mode.get_validator_address().unwrap().clone();

            let proposal = InitProposalData {
                content: Hash::default(),
                author: validator.clone(),
                voting_start_epoch: Epoch::default(),
                voting_end_epoch: Epoch::default().next(),
                activation_epoch: Epoch::default().next(),
                r#type: ProposalType::Default,
            };

            namada_sdk::governance::init_proposal::<_, token::Store<_>>(
                &mut shell.state,
                &proposal,
                vec![],
                None,
            )
            .unwrap();

            let vote = VoteProposalData {
                id: proposal_id,
                vote,
                voter: validator,
            };
            // Vote to accept the proposal (there's only one validator, so its
            // vote decides)
            namada_sdk::governance::vote_proposal(
                &mut shell.state,
                vote,
                HashSet::new(),
            )
            .unwrap();
        };

        // Add a proposal to be accepted and one to be rejected.
        add_proposal(0, ProposalVote::Yay);
        add_proposal(1, ProposalVote::Nay);

        // Commit the genesis state
        shell.state.commit_block().unwrap();
        shell.commit();

        // Collect all storage key-vals into a sorted map
        let store_block_state = |shell: &TestShell| -> BTreeMap<_, _> {
            shell
                .state
                .db()
                .iter_prefix(None)
                .map(|(key, val, _gas)| (key, val))
                .collect()
        };

        // Store the full state in sorted map
        let mut last_storage_state: std::collections::BTreeMap<
            String,
            Vec<u8>,
        > = store_block_state(&shell);

        // Keep applying finalize block
        let validator = shell.mode.get_validator_address().unwrap();
        let pos_params = read_pos_params(&shell.state).unwrap();
        let consensus_key =
            proof_of_stake::storage::validator_consensus_key_handle(validator)
                .get(&shell.state, Epoch::default(), &pos_params)
                .unwrap()
                .unwrap();
        let proposer_address = HEXUPPER
            .decode(consensus_key.tm_raw_hash().as_bytes())
            .unwrap();
        let val_stake = read_validator_stake(
            &shell.state,
            &pos_params,
            validator,
            Epoch::default(),
        )
        .unwrap();

        let votes = vec![VoteInfo {
            validator: Validator {
                address: proposer_address.clone().try_into().unwrap(),
                power: (u128::try_from(val_stake).expect("Test failed") as u64)
                    .try_into()
                    .unwrap(),
            },
            sig_info: tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];

        // Need to supply a proposer address and votes to flow through the
        // inflation code
        for _ in 0..20 {
            // Add some txs
            let mut txs = vec![];
            // create two wrapper txs
            for _ in 0..2 {
                let (_tx, processed_tx) = mk_wrapper_tx(&shell, &txs_key);
                txs.push(processed_tx);
            }

            let req = FinalizeBlock {
                txs,
                proposer_address: proposer_address.clone(),
                decided_last_commit: tendermint::abci::types::CommitInfo {
                    round: 0u8.into(),
                    votes: votes.clone(),
                },
                ..Default::default()
            };
            // merkle tree root before finalize_block
            let root_pre = shell.shell.state.in_mem().block.tree.root();

            let _events = shell.finalize_block(req).unwrap();

            // the merkle tree root should not change after finalize_block
            let root_post = shell.shell.state.in_mem().block.tree.root();
            assert_eq!(root_pre.0, root_post.0);
            let new_state = store_block_state(&shell);
            // The new state must be unchanged
            itertools::assert_equal(
                last_storage_state.iter(),
                new_state.iter(),
            );
            // Commit the block to move on to the next one
            shell.state.commit_block().unwrap();

            // Store the state after commit for the next iteration
            last_storage_state = store_block_state(&shell);
        }
    }

    /// A unit test for PoS inflationary rewards
    #[test]
    fn test_inflation_accounting() {
        // GENERAL IDEA OF THE TEST:
        // For the duration of an epoch, choose some number of times for each of
        // 4 genesis validators to propose a block and choose some arbitrary
        // voting distribution for each block. After each call of
        // finalize_block, check the validator rewards accumulators to ensure
        // that the proper inflation is being applied for each validator. Can
        // also check that the last and current block proposers are being stored
        // properly. At the end of the epoch, check that the validator rewards
        // products are appropriately updated.

        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators: 4,
            ..Default::default()
        });

        let mut validator_set: BTreeSet<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = read_pos_params(&shell.state).unwrap();

        let val1 = validator_set.pop_first().unwrap();
        let val2 = validator_set.pop_first().unwrap();
        let val3 = validator_set.pop_first().unwrap();
        let val4 = validator_set.pop_first().unwrap();

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.state, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            let vec = HEXUPPER.decode(hash_string.as_bytes()).unwrap();
            let res: [u8; 20] = TryFrom::try_from(vec).unwrap();
            res
        };

        let pkh1 = get_pkh(val1.address.clone(), Epoch::default());
        let pkh2 = get_pkh(val2.address.clone(), Epoch::default());
        let pkh3 = get_pkh(val3.address.clone(), Epoch::default());
        let pkh4 = get_pkh(val4.address.clone(), Epoch::default());

        // All validators sign blocks initially
        let votes = vec![
            VoteInfo {
                validator: Validator {
                    address: pkh1,
                    power: (u128::try_from(val1.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh2,
                    power: (u128::try_from(val2.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh3,
                    power: (u128::try_from(val3.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh4,
                    power: (u128::try_from(val4.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
        ];

        let rewards_prod_1 = validator_rewards_products_handle(&val1.address);
        let rewards_prod_2 = validator_rewards_products_handle(&val2.address);
        let rewards_prod_3 = validator_rewards_products_handle(&val3.address);
        let rewards_prod_4 = validator_rewards_products_handle(&val4.address);

        let is_decimal_equal_enough = |target: Dec, to_compare: Dec| -> bool {
            // also return false if to_compare > target since this should
            // never happen for the use cases
            if to_compare < target {
                let tolerance = Dec::new(1, POS_DECIMAL_PRECISION / 2)
                    .expect("Dec creation failed");
                let res = Dec::one() - to_compare / target;
                res < tolerance
            } else {
                to_compare == target
            }
        };

        // NOTE: Want to manually set the block proposer and the vote
        // information in a FinalizeBlock object. In non-abcipp mode,
        // the block proposer is written in ProcessProposal, so need to
        // manually do it here let proposer_address = pkh1.clone();

        // FINALIZE BLOCK 1. Tell Namada that val1 is the block proposer. We
        // won't receive votes from TM since we receive votes at a 1-block
        // delay, so votes will be empty here
        next_block_for_inflation(&mut shell, pkh1.to_vec(), vec![], None);
        assert!(rewards_accumulator_handle().is_empty(&shell.state).unwrap());

        // FINALIZE BLOCK 2. Tell Namada that val1 is the block proposer.
        // Include votes that correspond to block 1. Make val2 the next block's
        // proposer.
        next_block_for_inflation(
            &mut shell,
            pkh2.to_vec(),
            votes.clone(),
            None,
        );
        assert!(rewards_prod_1.is_empty(&shell.state).unwrap());
        assert!(rewards_prod_2.is_empty(&shell.state).unwrap());
        assert!(rewards_prod_3.is_empty(&shell.state).unwrap());
        assert!(rewards_prod_4.is_empty(&shell.state).unwrap());
        assert!(!rewards_accumulator_handle().is_empty(&shell.state).unwrap());
        // Val1 was the proposer, so its reward should be larger than all
        // others, which should themselves all be equal
        let acc_sum = get_rewards_sum(&shell.state);
        assert!(is_decimal_equal_enough(Dec::one(), acc_sum));
        let acc = get_rewards_acc(&shell.state);
        assert_eq!(acc.get(&val2.address), acc.get(&val3.address));
        assert_eq!(acc.get(&val2.address), acc.get(&val4.address));
        assert!(
            acc.get(&val1.address).cloned().unwrap()
                > acc.get(&val2.address).cloned().unwrap()
        );

        // FINALIZE BLOCK 3, with val1 as proposer for the next block.
        next_block_for_inflation(&mut shell, pkh1.to_vec(), votes, None);
        assert!(rewards_prod_1.is_empty(&shell.state).unwrap());
        assert!(rewards_prod_2.is_empty(&shell.state).unwrap());
        assert!(rewards_prod_3.is_empty(&shell.state).unwrap());
        assert!(rewards_prod_4.is_empty(&shell.state).unwrap());
        // Val2 was the proposer for this block, so its rewards accumulator
        // should be the same as val1 now. Val3 and val4 should be equal as
        // well.
        let acc_sum = get_rewards_sum(&shell.state);
        assert!(is_decimal_equal_enough(Dec::two(), acc_sum));
        let acc = get_rewards_acc(&shell.state);
        assert_eq!(acc.get(&val1.address), acc.get(&val2.address));
        assert_eq!(acc.get(&val3.address), acc.get(&val4.address));
        assert!(
            acc.get(&val1.address).cloned().unwrap()
                > acc.get(&val3.address).cloned().unwrap()
        );

        // Now we don't receive a vote from val4.
        let votes = vec![
            VoteInfo {
                validator: Validator {
                    address: pkh1,
                    power: (u128::try_from(val1.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh2,
                    power: (u128::try_from(val2.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh3,
                    power: (u128::try_from(val3.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh4,
                    power: (u128::try_from(val4.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info: tendermint::abci::types::BlockSignatureInfo::Flag(
                    tendermint::block::BlockIdFlag::Absent,
                ),
            },
        ];

        // FINALIZE BLOCK 4. The next block proposer will be val1. Only val1,
        // val2, and val3 vote on this block.
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes.clone(),
            None,
        );
        assert!(rewards_prod_1.is_empty(&shell.state).unwrap());
        assert!(rewards_prod_2.is_empty(&shell.state).unwrap());
        assert!(rewards_prod_3.is_empty(&shell.state).unwrap());
        assert!(rewards_prod_4.is_empty(&shell.state).unwrap());
        let acc_sum = get_rewards_sum(&shell.state);
        assert!(is_decimal_equal_enough(Dec::new(3, 0).unwrap(), acc_sum));
        let acc = get_rewards_acc(&shell.state);
        assert!(
            acc.get(&val1.address).cloned().unwrap()
                > acc.get(&val2.address).cloned().unwrap()
        );
        assert!(
            acc.get(&val2.address).cloned().unwrap()
                > acc.get(&val3.address).cloned().unwrap()
        );
        assert!(
            acc.get(&val3.address).cloned().unwrap()
                > acc.get(&val4.address).cloned().unwrap()
        );

        // Advance to the start of epoch 1. Val1 is the only block proposer for
        // the rest of the epoch. Val4 does not vote for the rest of the epoch.
        let height_of_next_epoch =
            shell.state.in_mem().next_epoch_min_start_height;
        let current_height = 4_u64;
        assert_eq!(current_height, shell.state.in_mem().block.height.0);

        for _ in current_height..height_of_next_epoch.0 + 2 {
            dbg!(get_rewards_acc(&shell.state), get_rewards_sum(&shell.state));
            next_block_for_inflation(
                &mut shell,
                pkh1.to_vec(),
                votes.clone(),
                None,
            );
        }
        assert!(rewards_accumulator_handle().is_empty(&shell.state).unwrap());
        let rp1 = rewards_prod_1
            .get(&shell.state, &Epoch::default())
            .unwrap()
            .unwrap();
        let rp2 = rewards_prod_2
            .get(&shell.state, &Epoch::default())
            .unwrap()
            .unwrap();
        let rp3 = rewards_prod_3
            .get(&shell.state, &Epoch::default())
            .unwrap()
            .unwrap();
        let rp4 = rewards_prod_4
            .get(&shell.state, &Epoch::default())
            .unwrap()
            .unwrap();
        assert!(rp1 > rp2);
        assert!(rp2 > rp3);
        assert!(rp3 > rp4);
    }

    /// A unit test for PoS inflationary rewards claiming and querying
    #[test]
    fn test_claim_rewards() {
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators: 1,
            ..Default::default()
        });

        let mut validator_set: BTreeSet<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = read_pos_params(&shell.state).unwrap();

        let validator = validator_set.pop_first().unwrap();

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.state, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            let decoded = HEXUPPER.decode(hash_string.as_bytes()).unwrap();
            TryFrom::try_from(decoded).unwrap()
        };

        let pkh1 = get_pkh(validator.address.clone(), Epoch::default());
        let votes = vec![VoteInfo {
            validator: Validator {
                address: pkh1,
                power: (u128::try_from(validator.bonded_stake).unwrap() as u64)
                    .try_into()
                    .unwrap(),
            },
            sig_info: tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];
        // let rewards_prod_1 =
        // validator_rewards_products_handle(&val1.address);

        let is_reward_equal_enough = |expected: token::Amount,
                                      actual: token::Amount,
                                      tolerance: u64|
         -> bool {
            let diff = expected - actual;
            diff <= tolerance.into()
        };

        let bond_id = BondId {
            source: validator.address.clone(),
            validator: validator.address.clone(),
        };
        let init_stake = validator.bonded_stake;

        let mut total_rewards = token::Amount::zero();
        let mut total_claimed = token::Amount::zero();

        // FINALIZE BLOCK 1. Tell Namada that val1 is the block proposer. We
        // won't receive votes from TM since we receive votes at a 1-block
        // delay, so votes will be empty here
        next_block_for_inflation(&mut shell, pkh1.to_vec(), vec![], None);
        assert!(rewards_accumulator_handle().is_empty(&shell.state).unwrap());

        let (current_epoch, inflation) =
            advance_epoch(&mut shell, &pkh1, &votes, None);
        total_rewards += inflation;

        // Query the available rewards
        let query_rewards =
            proof_of_stake::query_reward_tokens::<_, governance::Store<_>>(
                &shell.state,
                None,
                &validator.address,
                current_epoch,
            )
            .unwrap();

        // Claim the rewards from the initial epoch
        let reward_1 =
            proof_of_stake::claim_reward_tokens::<
                _,
                governance::Store<_>,
                token::Store<_>,
            >(
                &mut shell.state, None, &validator.address, current_epoch
            )
            .unwrap();
        total_claimed += reward_1;
        assert_eq!(reward_1, query_rewards);
        assert!(is_reward_equal_enough(total_rewards, total_claimed, 1));

        // Query the available rewards again and check that it is 0 now after
        // the claim
        let query_rewards =
            proof_of_stake::query_reward_tokens::<_, governance::Store<_>>(
                &shell.state,
                None,
                &validator.address,
                current_epoch,
            )
            .unwrap();
        assert_eq!(query_rewards, token::Amount::zero());

        // Try a claim the next block and ensure we get 0 tokens back
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes.clone(),
            None,
        );
        let att = proof_of_stake::claim_reward_tokens::<
            _,
            governance::Store<_>,
            token::Store<_>,
        >(
            &mut shell.state, None, &validator.address, current_epoch
        )
        .unwrap();
        assert_eq!(att, token::Amount::zero());

        // Go to the next epoch
        let (current_epoch, inflation) =
            advance_epoch(&mut shell, &pkh1, &votes, None);
        total_rewards += inflation;

        // Unbond some tokens
        let unbond_amount = token::Amount::native_whole(50_000);
        let unbond_res =
            proof_of_stake::unbond_tokens::<_, governance::Store<_>>(
                &mut shell.state,
                None,
                &validator.address,
                unbond_amount,
                current_epoch,
                false,
            )
            .unwrap();
        assert_eq!(unbond_res.sum, unbond_amount);

        // Query the available rewards
        let query_rewards =
            proof_of_stake::query_reward_tokens::<_, governance::Store<_>>(
                &shell.state,
                None,
                &validator.address,
                current_epoch,
            )
            .unwrap();

        let rew = proof_of_stake::claim_reward_tokens::<
            _,
            governance::Store<_>,
            token::Store<_>,
        >(
            &mut shell.state, None, &validator.address, current_epoch
        )
        .unwrap();
        total_claimed += rew;
        assert!(is_reward_equal_enough(total_rewards, total_claimed, 3));
        assert_eq!(query_rewards, rew);

        // Check the bond amounts for rewards up thru the withdrawable epoch
        let withdraw_epoch = current_epoch + params.withdrawable_epoch_offset();
        let last_claim_epoch =
            proof_of_stake::storage::get_last_reward_claim_epoch(
                &shell.state,
                &validator.address,
                &validator.address,
            )
            .unwrap();
        let bond_amounts = proof_of_stake::bond_amounts_for_rewards::<
            _,
            governance::Store<_>,
        >(
            &shell.state,
            &bond_id,
            last_claim_epoch.unwrap_or_default(),
            withdraw_epoch,
        )
        .unwrap();

        // Should only have the remaining amounts in bonds themselves
        let mut exp_bond_amounts = BTreeMap::<Epoch, token::Amount>::new();
        for epoch in Epoch::iter_bounds_inclusive(
            last_claim_epoch.unwrap_or_default(),
            withdraw_epoch,
        ) {
            exp_bond_amounts
                .insert(epoch, validator.bonded_stake - unbond_amount);
        }
        assert_eq!(exp_bond_amounts, bond_amounts);

        let pipeline_epoch_from_unbond = current_epoch + params.pipeline_len;

        // Advance to the withdrawable epoch
        let mut current_epoch = current_epoch;
        let mut missed_rewards = token::Amount::zero();
        while current_epoch < withdraw_epoch {
            let votes = get_default_true_votes(
                &shell.state,
                shell.state.in_mem().block.epoch,
            );
            let (new_epoch, inflation) =
                advance_epoch(&mut shell, &pkh1, &votes, None);
            current_epoch = new_epoch;

            total_rewards += inflation;
            if current_epoch <= pipeline_epoch_from_unbond {
                missed_rewards += inflation;
            }
        }

        // Withdraw tokens
        let withdraw_amount =
            proof_of_stake::withdraw_tokens::<
                _,
                governance::Store<_>,
                token::Store<_>,
            >(
                &mut shell.state, None, &validator.address, current_epoch
            )
            .unwrap();
        assert_eq!(withdraw_amount, unbond_amount);

        // Query the available rewards
        let query_rewards =
            proof_of_stake::query_reward_tokens::<_, governance::Store<_>>(
                &shell.state,
                None,
                &validator.address,
                current_epoch,
            )
            .unwrap();

        // Claim tokens
        let reward_2 =
            proof_of_stake::claim_reward_tokens::<
                _,
                governance::Store<_>,
                token::Store<_>,
            >(
                &mut shell.state, None, &validator.address, current_epoch
            )
            .unwrap();
        total_claimed += reward_2;
        assert_eq!(query_rewards, reward_2);

        // The total rewards claimed should be approximately equal to the total
        // minted inflation, minus (unbond_amount / initial_stake) * rewards
        // from the unbond epoch and the following epoch (the missed_rewards)
        let ratio = Dec::try_from(unbond_amount).unwrap()
            / Dec::try_from(init_stake).unwrap();
        let lost_rewards = ratio * missed_rewards;
        let uncertainty = Dec::from_str("0.07").unwrap();
        let token_uncertainty = uncertainty * lost_rewards;
        let token_diff = total_claimed + lost_rewards - total_rewards;
        assert!(token_diff < token_uncertainty);

        // Query the available rewards to check that they are 0
        let query_rewards =
            proof_of_stake::query_reward_tokens::<_, governance::Store<_>>(
                &shell.state,
                None,
                &validator.address,
                current_epoch,
            )
            .unwrap();
        assert_eq!(query_rewards, token::Amount::zero());
    }

    /// A unit test for PoS inflationary rewards claiming
    #[test]
    fn test_claim_validator_commissions() {
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators: 1,
            ..Default::default()
        });

        let mut validator_set: BTreeSet<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = read_pos_params(&shell.state).unwrap();

        let validator = validator_set.pop_first().unwrap();
        let commission_rate =
            proof_of_stake::storage::validator_commission_rate_handle(
                &validator.address,
            )
            .get(&shell.state, Epoch(0), &params)
            .unwrap()
            .unwrap();

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.state, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            HEXUPPER.decode(hash_string.as_bytes()).unwrap()
        };

        let pkh1 = get_pkh(validator.address.clone(), Epoch::default());

        let is_reward_equal_enough = |expected: token::Amount,
                                      actual: token::Amount,
                                      tolerance: u64|
         -> bool {
            let diff = expected - actual;
            diff <= tolerance.into()
        };

        let init_stake = validator.bonded_stake;

        let mut total_rewards = token::Amount::zero();
        let mut total_claimed = token::Amount::zero();

        // FINALIZE BLOCK 1. Tell Namada that val1 is the block proposer. We
        // won't receive votes from TM since we receive votes at a 1-block
        // delay, so votes will be empty here
        next_block_for_inflation(&mut shell, pkh1.clone(), vec![], None);
        assert!(rewards_accumulator_handle().is_empty(&shell.state).unwrap());

        // Make an account with balance and delegate some tokens
        let delegator = address::testing::gen_implicit_address();
        let del_amount = init_stake;
        let staking_token = shell.state.in_mem().native_token.clone();
        namada_sdk::token::credit_tokens(
            &mut shell.state,
            &staking_token,
            &delegator,
            2 * init_stake,
        )
        .unwrap();
        let mut current_epoch = shell.state.in_mem().block.epoch;
        bond_tokens::<_, governance::Store<_>, token::Store<_>>(
            &mut shell.state,
            Some(&delegator),
            &validator.address,
            del_amount,
            current_epoch,
            None,
        )
        .unwrap();

        // Advance to pipeline epoch
        for _ in 0..params.pipeline_len {
            let votes = get_default_true_votes(
                &shell.state,
                shell.state.in_mem().block.epoch,
            );
            let (new_epoch, inflation) =
                advance_epoch(&mut shell, &pkh1, &votes, None);
            current_epoch = new_epoch;
            total_rewards += inflation;
        }

        // Claim the rewards for the validator for the first two epochs
        let val_reward_1 =
            proof_of_stake::claim_reward_tokens::<
                _,
                governance::Store<_>,
                token::Store<_>,
            >(
                &mut shell.state, None, &validator.address, current_epoch
            )
            .unwrap();
        total_claimed += val_reward_1;
        assert!(is_reward_equal_enough(
            total_rewards,
            total_claimed,
            current_epoch.0
        ));

        // Go to the next epoch, where now the delegator's stake has been active
        // for an epoch
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        let (new_epoch, inflation_3) =
            advance_epoch(&mut shell, &pkh1, &votes, None);
        current_epoch = new_epoch;
        total_rewards += inflation_3;

        // Claim again for the validator
        let val_reward_2 =
            proof_of_stake::claim_reward_tokens::<
                _,
                governance::Store<_>,
                token::Store<_>,
            >(
                &mut shell.state, None, &validator.address, current_epoch
            )
            .unwrap();

        // Claim for the delegator
        let del_reward_1 = proof_of_stake::claim_reward_tokens::<
            _,
            governance::Store<_>,
            token::Store<_>,
        >(
            &mut shell.state,
            Some(&delegator),
            &validator.address,
            current_epoch,
        )
        .unwrap();

        // Check that both claims add up to the inflation minted in the last
        // epoch
        assert!(is_reward_equal_enough(
            inflation_3,
            val_reward_2 + del_reward_1,
            current_epoch.0
        ));

        // Check that the commission earned is expected
        let del_stake = Dec::try_from(del_amount).unwrap();
        let tot_stake = Dec::try_from(init_stake + del_amount).unwrap();
        let stake_ratio = del_stake / tot_stake;
        let del_rewards_no_commission = stake_ratio * inflation_3;
        let commission = commission_rate * del_rewards_no_commission;
        let exp_val_reward =
            (Dec::one() - stake_ratio) * inflation_3 + commission;
        let exp_del_reward = del_rewards_no_commission - commission;

        assert!(is_reward_equal_enough(exp_val_reward, val_reward_2, 1));
        assert!(is_reward_equal_enough(exp_del_reward, del_reward_1, 1));
    }

    /// A unit test for changing consensus keys and communicating to CometBFT
    #[test]
    fn test_change_validator_consensus_key() {
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators: 3,
            ..Default::default()
        });

        let mut validators: BTreeSet<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = read_pos_params(&shell.state).unwrap();
        let mut current_epoch = shell.state.in_mem().block.epoch;

        let validator1 = validators.pop_first().unwrap();
        let validator2 = validators.pop_first().unwrap();
        let validator3 = validators.pop_first().unwrap();

        let init_stake = validator1.bonded_stake;

        // Give the validators some tokens for txs
        let staking_token = shell.state.in_mem().native_token.clone();
        namada_sdk::token::credit_tokens(
            &mut shell.state,
            &staking_token,
            &validator1.address,
            init_stake,
        )
        .unwrap();
        namada_sdk::token::credit_tokens(
            &mut shell.state,
            &staking_token,
            &validator2.address,
            init_stake,
        )
        .unwrap();
        namada_sdk::token::credit_tokens(
            &mut shell.state,
            &staking_token,
            &validator3.address,
            init_stake,
        )
        .unwrap();

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.state, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            HEXUPPER.decode(hash_string.as_bytes()).unwrap()
        };
        let pkh1 = get_pkh(validator1.address.clone(), Epoch::default());

        // FINALIZE BLOCK 1. Tell Namada that val1 is the block proposer. We
        // won't receive votes from TM since we receive votes at a 1-block
        // delay, so votes will be empty here
        next_block_for_inflation(&mut shell, pkh1.clone(), vec![], None);
        assert!(rewards_accumulator_handle().is_empty(&shell.state).unwrap());

        // Check that there's 3 unique consensus keys
        let consensus_keys =
            proof_of_stake::storage::get_consensus_key_set(&shell.state)
                .unwrap();
        assert_eq!(consensus_keys.len(), 3);
        // let ck1 = validator_consensus_key_handle(&validator)
        //     .get(&storage, current_epoch, &params)
        //     .unwrap()
        //     .unwrap();
        // assert_eq!(ck, og_ck);

        // Let one validator update stake, one change consensus key, and then
        // one do both

        // Validator1 bonds 1 NAM
        let bond_amount = token::Amount::native_whole(1);
        bond_tokens::<_, governance::Store<_>, token::Store<_>>(
            &mut shell.state,
            None,
            &validator1.address,
            bond_amount,
            current_epoch,
            None,
        )
        .unwrap();

        // Validator2 changes consensus key
        let new_ck2 = common_sk_from_simple_seed(1).ref_to();
        proof_of_stake::change_consensus_key::<_, governance::Store<_>>(
            &mut shell.state,
            &validator2.address,
            &new_ck2,
            current_epoch,
        )
        .unwrap();

        // Validator3 bonds 1 NAM and changes consensus key
        bond_tokens::<_, governance::Store<_>, token::Store<_>>(
            &mut shell.state,
            None,
            &validator3.address,
            bond_amount,
            current_epoch,
            None,
        )
        .unwrap();
        let new_ck3 = common_sk_from_simple_seed(2).ref_to();
        proof_of_stake::change_consensus_key::<_, governance::Store<_>>(
            &mut shell.state,
            &validator3.address,
            &new_ck3,
            current_epoch,
        )
        .unwrap();

        // Check that there's 5 unique consensus keys
        let consensus_keys =
            proof_of_stake::storage::get_consensus_key_set(&shell.state)
                .unwrap();
        assert_eq!(consensus_keys.len(), 5);

        // Advance to pipeline epoch
        for _ in 0..params.pipeline_len {
            let votes = get_default_true_votes(
                &shell.state,
                shell.state.in_mem().block.epoch,
            );
            let (new_epoch, _inflation) =
                advance_epoch(&mut shell, &pkh1, &votes, None);
            current_epoch = new_epoch;
        }

        let consensus_vals = read_consensus_validator_set_addresses_with_stake(
            &shell.state,
            current_epoch,
        )
        .unwrap();
        let exp_vals = vec![
            WeightedValidator {
                address: validator1.address.clone(),
                bonded_stake: init_stake + bond_amount,
            },
            WeightedValidator {
                address: validator2.address.clone(),
                bonded_stake: init_stake,
            },
            WeightedValidator {
                address: validator3.address.clone(),
                bonded_stake: init_stake + bond_amount,
            },
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(consensus_vals, exp_vals);

        // Val 1 changes consensus key
        let new_ck1 = common_sk_from_simple_seed(3).ref_to();
        proof_of_stake::change_consensus_key::<_, governance::Store<_>>(
            &mut shell.state,
            &validator1.address,
            &new_ck1,
            current_epoch,
        )
        .unwrap();

        // Val 2 is fully unbonded
        proof_of_stake::unbond_tokens::<_, governance::Store<_>>(
            &mut shell.state,
            None,
            &validator2.address,
            init_stake,
            current_epoch,
            false,
        )
        .unwrap();

        // Val 3 is fully unbonded and changes consensus key
        proof_of_stake::unbond_tokens::<_, governance::Store<_>>(
            &mut shell.state,
            None,
            &validator3.address,
            init_stake + bond_amount,
            current_epoch,
            false,
        )
        .unwrap();
        let new2_ck3 = common_sk_from_simple_seed(4).ref_to();
        proof_of_stake::change_consensus_key::<_, governance::Store<_>>(
            &mut shell.state,
            &validator1.address,
            &new2_ck3,
            current_epoch,
        )
        .unwrap();

        // Check that there's 7 unique consensus keys
        let consensus_keys =
            proof_of_stake::storage::get_consensus_key_set(&shell.state)
                .unwrap();
        assert_eq!(consensus_keys.len(), 7);

        // Advance to pipeline epoch
        for _ in 0..params.pipeline_len {
            let votes = get_default_true_votes(
                &shell.state,
                shell.state.in_mem().block.epoch,
            );
            let (new_epoch, _inflation) =
                advance_epoch(&mut shell, &pkh1, &votes, None);
            current_epoch = new_epoch;
        }

        let consensus_vals = read_consensus_validator_set_addresses_with_stake(
            &shell.state,
            current_epoch,
        )
        .unwrap();
        let exp_vals = vec![WeightedValidator {
            address: validator1.address.clone(),
            bonded_stake: init_stake + bond_amount,
        }]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(consensus_vals, exp_vals);

        // Now promote the below-threshold validators back into the consensus
        // set, along with consensus key changes

        // Val2 bonds 1 NAM and changes consensus key
        bond_tokens::<_, governance::Store<_>, token::Store<_>>(
            &mut shell.state,
            None,
            &validator2.address,
            bond_amount,
            current_epoch,
            None,
        )
        .unwrap();
        let new2_ck2 = common_sk_from_simple_seed(5).ref_to();
        proof_of_stake::change_consensus_key::<_, governance::Store<_>>(
            &mut shell.state,
            &validator2.address,
            &new2_ck2,
            current_epoch,
        )
        .unwrap();

        // Val3 bonds 1 NAM
        bond_tokens::<_, governance::Store<_>, token::Store<_>>(
            &mut shell.state,
            None,
            &validator3.address,
            bond_amount,
            current_epoch,
            None,
        )
        .unwrap();

        // Check that there's 8 unique consensus keys
        let consensus_keys =
            proof_of_stake::storage::get_consensus_key_set(&shell.state)
                .unwrap();
        assert_eq!(consensus_keys.len(), 8);

        // Advance to pipeline epoch
        for _ in 0..params.pipeline_len {
            let votes = get_default_true_votes(
                &shell.state,
                shell.state.in_mem().block.epoch,
            );
            let (new_epoch, _inflation) =
                advance_epoch(&mut shell, &pkh1, &votes, None);
            current_epoch = new_epoch;
        }

        let consensus_vals = read_consensus_validator_set_addresses_with_stake(
            &shell.state,
            current_epoch,
        )
        .unwrap();
        let exp_vals = vec![
            WeightedValidator {
                address: validator1.address,
                bonded_stake: init_stake + bond_amount,
            },
            WeightedValidator {
                address: validator2.address,
                bonded_stake: bond_amount,
            },
            WeightedValidator {
                address: validator3.address,
                bonded_stake: bond_amount,
            },
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(consensus_vals, exp_vals);
    }

    fn get_rewards_acc<S>(storage: &S) -> HashMap<Address, Dec>
    where
        S: StorageRead,
    {
        rewards_accumulator_handle()
            .iter(storage)
            .unwrap()
            .map(|elem| elem.unwrap())
            .collect::<HashMap<Address, Dec>>()
    }

    fn get_rewards_sum<S>(storage: &S) -> Dec
    where
        S: StorageRead,
    {
        let acc = get_rewards_acc(storage);
        if acc.is_empty() {
            Dec::zero()
        } else {
            acc.iter().fold(Dec::zero(), |sum, elm| sum + *elm.1)
        }
    }

    /// Test that replay protection keys are not added to the merkle tree
    #[test]
    fn test_replay_keys_not_merklized() {
        let (mut shell, _, _, _) = setup();

        let (wrapper_tx, processed_tx) = mk_wrapper_tx(
            &shell,
            &namada_apps_lib::wallet::defaults::albert_keypair(),
        );

        let wrapper_hash_key =
            replay_protection::current_key(&wrapper_tx.header_hash());

        // merkle tree root before finalize_block
        let root_pre = shell.shell.state.in_mem().block.tree.root();

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")[0];
        assert_eq!(*event.kind(), APPLIED_TX);
        let code = event.read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.state.in_mem().block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        // Check transaction's hash in storage
        assert!(
            shell
                .shell
                .state
                .write_log()
                .has_replay_protection_entry(&wrapper_tx.raw_header_hash())
        );
        // Check that the hash is not present in the merkle tree
        shell.state.commit_block().unwrap();
        assert!(
            !shell
                .shell
                .state
                .in_mem()
                .block
                .tree
                .has_key(&wrapper_hash_key)
                .unwrap()
        );

        // test that a commitment to replay protection gets added.
        let reprot_key = replay_protection::commitment_key();
        let reprot_commitment: Hash = shell
            .state
            .read(&reprot_key)
            .expect("Test failed")
            .expect("Test failed");
        assert_eq!(wrapper_tx.raw_header_hash(), reprot_commitment);
    }

    /// Test that masp anchor keys are added to the merkle tree
    #[test]
    fn test_masp_anchors_merklized() {
        let (mut shell, _, _, _) = setup();

        let convert_key =
            namada_sdk::token::storage_key::masp_convert_anchor_key();
        let commitment_key =
            namada_sdk::token::storage_key::masp_commitment_anchor_key(0);

        // merkle tree root before finalize_block
        let root_pre = shell.shell.state.in_mem().block.tree.root();

        // Manually change the anchors
        shell
            .state
            .write_log_mut()
            .protocol_write(&convert_key, "random_data".serialize_to_vec())
            .unwrap();
        shell
            .state
            .write_log_mut()
            .protocol_write(&commitment_key, "random_data".serialize_to_vec())
            .unwrap();
        shell
            .finalize_block(FinalizeBlock {
                txs: vec![],
                ..Default::default()
            })
            .expect("Test failed");

        // the merkle tree root should change after finalize_block
        let root_post = shell.shell.state.in_mem().block.tree.root();
        assert_eq!(root_pre.0, root_post.0);
        // Check that the hashes are present in the merkle tree
        shell.state.commit_block().unwrap();
        assert!(
            shell
                .shell
                .state
                .in_mem()
                .block
                .tree
                .has_key(&convert_key)
                .unwrap()
        );
        assert!(
            shell
                .shell
                .state
                .in_mem()
                .block
                .tree
                .has_key(&commitment_key)
                .unwrap()
        );
    }

    /// Test that a tx that has already been applied in the same block
    /// doesn't get reapplied
    #[test]
    fn test_duplicated_tx_same_block() {
        let (mut shell, _broadcaster, _, _) = setup();
        let keypair = namada_apps_lib::wallet::defaults::albert_keypair();
        let keypair_2 = namada_apps_lib::wallet::defaults::bertha_keypair();

        let tx_code = TestWasms::TxNoOp.read_bytes();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                WRAPPER_GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new(tx_code, None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));

        let mut new_wrapper = wrapper.clone();
        new_wrapper.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(1.into()),
                token: shell.state.in_mem().native_token.clone(),
            },
            keypair_2.ref_to(),
            WRAPPER_GAS_LIMIT.into(),
        ))));
        new_wrapper.add_section(Section::Authorization(Authorization::new(
            new_wrapper.sechashes(),
            [(0, keypair_2)].into_iter().collect(),
            None,
        )));
        wrapper.add_section(Section::Authorization(Authorization::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let mut processed_txs: Vec<ProcessedTx> = vec![];
        for tx in [&wrapper, &new_wrapper] {
            processed_txs.push(ProcessedTx {
                tx: tx.to_bytes().into(),
                result: TxResult {
                    code: ResultCode::Ok.into(),
                    info: "".into(),
                },
            })
        }

        // merkle tree root before finalize_block
        let root_pre = shell.shell.state.in_mem().block.tree.root();

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.state.in_mem().block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        assert_eq!(*event[0].kind(), APPLIED_TX);
        let code = event[0].read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);
        assert_eq!(*event[1].kind(), APPLIED_TX);
        let code = event[1].read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::WasmRuntimeError);

        for wrapper in [&wrapper, &new_wrapper] {
            assert!(
                shell
                    .state
                    .write_log()
                    .has_replay_protection_entry(&wrapper.raw_header_hash())
            );
            assert!(
                !shell
                    .state
                    .write_log()
                    .has_replay_protection_entry(&wrapper.header_hash())
            );
        }
        // Commit to check the hashes from storage
        shell.commit();
        for wrapper in [&wrapper, &new_wrapper] {
            assert!(
                shell
                    .state
                    .has_replay_protection_entry(&wrapper.raw_header_hash())
                    .unwrap()
            );
            assert!(
                !shell
                    .state
                    .has_replay_protection_entry(&wrapper.header_hash())
                    .unwrap()
            );
        }
    }

    // Test two identical txs in the same block. The first one fails but doesn't
    // write the hash (because of invalid signature). The second one must be
    // able to execute and pass
    #[test]
    fn test_duplicated_tx_same_block_with_failure() {
        let (mut shell, _, _, _) = setup();
        let keypair = namada_apps_lib::wallet::defaults::albert_keypair();
        let keypair_2 = namada_apps_lib::wallet::defaults::bertha_keypair();

        let tx_code = TestWasms::TxWriteStorageKey.read_bytes();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                WRAPPER_GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new(tx_code, None));
        let key = Key::from(Address::from(&keypair_2.ref_to()).to_db_key())
            .push(&"test".to_string())
            .unwrap();
        wrapper.set_data(Data::new(
            TxWriteData {
                key,
                value: "test".as_bytes().to_vec(),
            }
            .serialize_to_vec(),
        ));

        let mut new_wrapper = wrapper.clone();
        new_wrapper.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(1.into()),
                token: shell.state.in_mem().native_token.clone(),
            },
            keypair_2.ref_to(),
            WRAPPER_GAS_LIMIT.into(),
        ))));
        new_wrapper.add_section(Section::Authorization(Authorization::new(
            vec![new_wrapper.raw_header_hash()],
            [(0, keypair_2.clone())].into_iter().collect(),
            None,
        )));
        // This is a signature coming from the wrong signer which will be
        // rejected by the vp
        wrapper.add_section(Section::Authorization(Authorization::new(
            vec![wrapper.raw_header_hash()],
            [(0, keypair.clone())].into_iter().collect(),
            None,
        )));
        new_wrapper.add_section(Section::Authorization(Authorization::new(
            new_wrapper.sechashes(),
            [(0, keypair_2)].into_iter().collect(),
            None,
        )));
        wrapper.add_section(Section::Authorization(Authorization::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let mut processed_txs: Vec<ProcessedTx> = vec![];
        for tx in [&wrapper, &new_wrapper] {
            processed_txs.push(ProcessedTx {
                tx: tx.to_bytes().into(),
                result: TxResult {
                    code: ResultCode::Ok.into(),
                    info: "".into(),
                },
            })
        }

        // merkle tree root before finalize_block
        let root_pre = shell.shell.state.in_mem().block.tree.root();

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.state.in_mem().block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        assert_eq!(*event[0].kind(), APPLIED_TX);
        let code = event[0].read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);
        let inner_tx_result = event[0].read_attribute::<Batch<'_>>().unwrap();
        let first_tx_result = inner_tx_result
            .get_inner_tx_result(
                Some(&wrapper.header_hash()),
                either::Right(wrapper.first_commitments().unwrap()),
            )
            .unwrap();
        assert!(first_tx_result.as_ref().is_ok_and(|res| !res.is_accepted()));
        assert_eq!(*event[1].kind(), APPLIED_TX);
        let code = event[1].read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);

        // This hash must be present as succesfully added by the second
        // transaction
    }

    /// Test that if a transaction fails because of out-of-gas, invalid
    /// signature or wrong section commitment, its hash is not committed to
    /// storage. Also checks that a tx failing for other reasons has its
    /// hash written to storage.
    #[test]
    fn test_tx_hash_handling() {
        let (mut shell, _broadcaster, _, _) = setup();
        let keypair = namada_apps_lib::wallet::defaults::bertha_keypair();
        let mut out_of_gas_wrapper = {
            let mut wrapper_tx =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            1.into(),
                        ),
                        token: shell.state.in_mem().native_token.clone(),
                    },
                    keypair.ref_to(),
                    0.into(),
                ))));
            wrapper_tx.header.chain_id = shell.chain_id.clone();
            wrapper_tx
                .set_data(Data::new("transaction data".as_bytes().to_owned()));
            wrapper_tx.add_code(TestWasms::TxNoOp.read_bytes(), None);
            wrapper_tx.sign_wrapper(keypair.clone());
            wrapper_tx
        };

        let mut unsigned_wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Amount::zero(),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                WRAPPER_GAS_LIMIT.into(),
            ))));
        unsigned_wrapper.header.chain_id = shell.chain_id.clone();

        let mut failing_wrapper = unsigned_wrapper.clone();

        let addr = Address::from(&keypair.to_public());
        // Write a key to trigger the vp to validate the signature
        let key = Key::from(addr.to_db_key())
            .join(&Key::from("test".to_string().to_db_key()));
        unsigned_wrapper
            .add_code(TestWasms::TxWriteStorageKey.read_bytes(), None)
            .add_data(TxWriteData {
                key,
                value: "test".as_bytes().to_owned(),
            });

        failing_wrapper
            .add_code(TestWasms::TxFail.read_bytes(), None)
            .add_data("transaction data");

        let mut wrong_commitment_wrapper = failing_wrapper.clone();
        let tx_code = TestWasms::TxInvalidData.read_bytes();
        wrong_commitment_wrapper.set_code(Code::new(tx_code, None));
        wrong_commitment_wrapper
            .sections
            .retain(|sec| !matches!(sec, Section::Data(_)));
        // Add some extra data to avoid having the same Tx hash as the
        // `failing_wrapper`
        wrong_commitment_wrapper.add_memo(&[0_u8]);

        let mut processed_txs: Vec<ProcessedTx> = vec![];
        for tx in [
            &mut out_of_gas_wrapper,
            &mut wrong_commitment_wrapper,
            &mut failing_wrapper,
        ] {
            tx.sign_raw(
                vec![keypair.clone()],
                vec![keypair.ref_to()].into_iter().collect(),
                None,
            );
        }
        for tx in [
            &mut out_of_gas_wrapper,
            &mut unsigned_wrapper,
            &mut wrong_commitment_wrapper,
            &mut failing_wrapper,
        ] {
            tx.sign_wrapper(keypair.clone());
            processed_txs.push(ProcessedTx {
                tx: tx.to_bytes().into(),
                result: TxResult {
                    code: ResultCode::Ok.into(),
                    info: "".into(),
                },
            })
        }

        // merkle tree root before finalize_block
        let root_pre = shell.shell.state.in_mem().block.tree.root();

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.state.in_mem().block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        assert_eq!(*event[0].kind(), APPLIED_TX);
        let code = event[0].read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::InvalidTx);
        assert_eq!(*event[1].kind(), APPLIED_TX);
        let code = event[1].read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);
        let inner_tx_result = event[1].read_attribute::<Batch<'_>>().unwrap();
        let inner_result = inner_tx_result
            .get_inner_tx_result(
                Some(&unsigned_wrapper.header_hash()),
                either::Right(unsigned_wrapper.first_commitments().unwrap()),
            )
            .unwrap();
        assert!(inner_result.as_ref().is_ok_and(|res| !res.is_accepted()));
        assert_eq!(*event[2].kind(), APPLIED_TX);
        let code = event[2].read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);
        let inner_tx_result = event[2].read_attribute::<Batch<'_>>().unwrap();
        let inner_result = inner_tx_result
            .get_inner_tx_result(
                Some(&wrong_commitment_wrapper.header_hash()),
                either::Right(
                    wrong_commitment_wrapper.first_commitments().unwrap(),
                ),
            )
            .unwrap();
        assert!(inner_result.is_err());
        assert_eq!(*event[3].kind(), APPLIED_TX);
        let code = event[3].read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);
        let inner_tx_result = event[3].read_attribute::<Batch<'_>>().unwrap();
        let inner_result = inner_tx_result
            .get_inner_tx_result(
                Some(&failing_wrapper.header_hash()),
                either::Right(failing_wrapper.first_commitments().unwrap()),
            )
            .unwrap();
        assert!(inner_result.is_err());

        for valid_wrapper in [
            &out_of_gas_wrapper,
            &unsigned_wrapper,
            &wrong_commitment_wrapper,
        ] {
            assert!(
                !shell.state.write_log().has_replay_protection_entry(
                    &valid_wrapper.raw_header_hash()
                )
            );
            assert!(
                shell
                    .state
                    .write_log()
                    .has_replay_protection_entry(&valid_wrapper.header_hash())
            );
        }
        assert!(
            shell.state.write_log().has_replay_protection_entry(
                &failing_wrapper.raw_header_hash()
            )
        );
        assert!(
            !shell
                .state
                .write_log()
                .has_replay_protection_entry(&failing_wrapper.header_hash())
        );

        // Commit to check the hashes from storage
        shell.commit();
        for valid_wrapper in [
            out_of_gas_wrapper,
            unsigned_wrapper,
            wrong_commitment_wrapper,
        ] {
            assert!(
                !shell
                    .state
                    .has_replay_protection_entry(
                        &valid_wrapper.raw_header_hash()
                    )
                    .unwrap()
            );
            assert!(
                shell
                    .state
                    .has_replay_protection_entry(&valid_wrapper.header_hash())
                    .unwrap()
            );
        }
        assert!(
            shell
                .state
                .has_replay_protection_entry(&failing_wrapper.raw_header_hash())
                .unwrap()
        );
        assert!(
            !shell
                .state
                .has_replay_protection_entry(&failing_wrapper.header_hash())
                .unwrap()
        );
    }

    #[test]
    /// Test that the hash of the wrapper transaction is committed to storage
    /// even if the wrapper tx fails. The inner transaction hash must not be
    /// inserted
    fn test_commits_hash_if_wrapper_failure() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();

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
        wrapper.add_section(Section::Authorization(Authorization::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let wrapper_hash = wrapper.header_hash();

        // Invalid wrapper tx that should lead to a commitment of the wrapper
        // hash and no commitment of the inner hash
        let processed_txs = vec![ProcessedTx {
            tx: wrapper.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        }];
        // merkle tree root before finalize_block
        let root_pre = shell.shell.state.in_mem().block.tree.root();

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.state.in_mem().block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        assert_eq!(*event[0].kind(), APPLIED_TX);
        let code = event[0].read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::InvalidTx);

        assert!(
            shell
                .state
                .write_log()
                .has_replay_protection_entry(&wrapper_hash)
        );
        assert!(
            !shell
                .state
                .write_log()
                .has_replay_protection_entry(&wrapper.raw_header_hash())
        );
    }

    // Test that the fees are paid even if the inner transaction fails and its
    // modifications are dropped
    #[test]
    fn test_fee_payment_if_invalid_inner_tx() {
        let (mut shell, _, _, _) = setup();
        let keypair = namada_apps_lib::wallet::defaults::albert_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                WRAPPER_GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new(TestWasms::TxFail.read_bytes(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Authorization(Authorization::new(
            wrapper.sechashes(),
            [(0, keypair.clone())].into_iter().collect(),
            None,
        )));

        let fee_amount =
            wrapper.header().wrapper().unwrap().get_tx_fee().unwrap();
        let fee_amount = namada_sdk::token::denom_to_amount(
            fee_amount,
            &wrapper.header().wrapper().unwrap().fee.token,
            &shell.state,
        )
        .unwrap();
        let signer_balance = namada_sdk::token::read_balance(
            &shell.state,
            &shell.state.in_mem().native_token,
            &wrapper.header().wrapper().unwrap().fee_payer(),
        )
        .unwrap();

        let processed_tx = ProcessedTx {
            tx: wrapper.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        };

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")[0];

        // Check balance of fee payer
        assert_eq!(*event.kind(), APPLIED_TX);
        let code = event.read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);
        let inner_tx_result = event.read_attribute::<Batch<'_>>().unwrap();
        let inner_result = inner_tx_result
            .get_inner_tx_result(
                Some(&wrapper.header_hash()),
                either::Right(wrapper.first_commitments().unwrap()),
            )
            .unwrap();
        assert!(inner_result.is_err());

        let new_signer_balance = namada_sdk::token::read_balance(
            &shell.state,
            &shell.state.in_mem().native_token,
            &wrapper.header().wrapper().unwrap().fee_payer(),
        )
        .unwrap();
        assert_eq!(
            new_signer_balance,
            signer_balance.checked_sub(fee_amount).unwrap()
        )
    }

    // Test that if the fee payer doesn't have enough funds for fee payment none
    // of the inner txs of the batch gets executed
    #[test]
    fn test_fee_payment_if_insufficient_balance() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();
        let native_token = shell.state.in_mem().native_token.clone();

        // Credit some tokens for fee payment
        let initial_balance: token::Amount = 1.into();
        namada_sdk::token::credit_tokens(
            &mut shell.state,
            &native_token,
            &Address::from(&keypair.to_public()),
            initial_balance,
        )
        .unwrap();
        let balance = read_balance(
            &shell.state,
            &native_token,
            &Address::from(&keypair.to_public()),
        )
        .unwrap();
        assert_eq!(balance, initial_balance);

        let (batch, processed_tx) =
            mk_tx_batch(&shell, &keypair, false, false, false);

        // Check that the fees are higher than the initial balance of the fee
        // payer
        let fee_amount =
            batch.header().wrapper().unwrap().get_tx_fee().unwrap();
        let fee_amount = namada_sdk::token::denom_to_amount(
            fee_amount,
            &batch.header().wrapper().unwrap().fee.token,
            &shell.state,
        )
        .unwrap();
        assert!(fee_amount > initial_balance);

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")[0];

        // Check balance of fee payer is unchanged
        assert_eq!(*event.kind(), APPLIED_TX);
        let code = event.read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::InvalidTx);
        let balance = read_balance(
            &shell.state,
            &native_token,
            &Address::from(&keypair.to_public()),
        )
        .unwrap();

        assert_eq!(balance, initial_balance);

        // Check that none of the txs of the batch have been executed (batch
        // attribute is missing)
        assert!(event.read_attribute::<Batch<'_>>().is_err());

        // Check storage modifications are missing
        for key in ["random_key_1", "random_key_2", "random_key_3"] {
            assert!(!shell.state.has_key(&key.parse().unwrap()).unwrap());
        }
    }

    // Test that paying fees with a whitelisted token which is not the native
    // one is accepted
    #[test]
    fn test_fee_payment_whitelisted_token() {
        let (mut shell, _, _, _) = setup();
        let btc = namada_sdk::address::testing::btc();
        let btc_denom = read_denom(&shell.state, &btc).unwrap().unwrap();
        let fee_amount: Amount = WRAPPER_GAS_LIMIT.into();

        // Credit some tokens for fee payment
        namada_sdk::token::credit_tokens(
            &mut shell.state,
            &btc,
            &Address::from(&albert_keypair().to_public()),
            fee_amount,
        )
        .unwrap();
        let balance = read_balance(
            &shell.state,
            &btc,
            &Address::from(&albert_keypair().to_public()),
        )
        .unwrap();
        assert_eq!(balance, fee_amount.clone());

        // Whitelist BTC for fee payment
        let gas_cost_key = namada_sdk::parameters::storage::get_gas_cost_key();
        let mut gas_prices: BTreeMap<Address, Amount> =
            shell.read_storage_key(&gas_cost_key).unwrap();
        gas_prices.insert(btc.clone(), 1.into());
        shell.shell.state.write(&gas_cost_key, gas_prices).unwrap();
        shell.commit();

        // Submit tx
        let mut tx = Tx::new(shell.chain_id.clone(), None);
        tx.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::new(
                    1.into(),
                    btc_denom,
                ),
                token: btc.clone(),
            },
            albert_keypair().ref_to(),
            WRAPPER_GAS_LIMIT.into(),
        ))));
        tx.add_code(TestWasms::TxNoOp.read_bytes(), None)
            .add_data("Transaction data");
        tx.sign_wrapper(albert_keypair());

        let processed_tx = ProcessedTx {
            tx: tx.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        };

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")[0];

        // Check fee payment
        assert_eq!(*event.kind(), APPLIED_TX);
        let code = event.read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);

        // Check fee payer balance
        let balance = read_balance(
            &shell.state,
            &btc,
            &Address::from(&albert_keypair().to_public()),
        )
        .unwrap();
        assert_eq!(balance, 0.into());
    }

    // Test that the fees collected from a block are withdrew from the wrapper
    // signer and credited to the block proposer
    #[test]
    fn test_fee_payment_to_block_proposer() {
        let (mut shell, _, _, _) = setup();

        let validator = shell.mode.get_validator_address().unwrap().to_owned();
        let pos_params = read_pos_params(&shell.state).unwrap();
        let consensus_key =
            proof_of_stake::storage::validator_consensus_key_handle(&validator)
                .get(&shell.state, Epoch::default(), &pos_params)
                .unwrap()
                .unwrap();
        let proposer_address = HEXUPPER
            .decode(consensus_key.tm_raw_hash().as_bytes())
            .unwrap();

        let proposer_balance = namada_sdk::token::read_balance(
            &shell.state,
            &shell.state.in_mem().native_token,
            &validator,
        )
        .unwrap();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                namada_apps_lib::wallet::defaults::albert_keypair().ref_to(),
                5_000_000.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper
            .add_code(TestWasms::TxNoOp.read_bytes(), None)
            .add_data("Transaction data");
        wrapper.sign_wrapper(albert_keypair());
        let fee_amount =
            wrapper.header().wrapper().unwrap().get_tx_fee().unwrap();
        let fee_amount = namada_sdk::token::denom_to_amount(
            fee_amount,
            &wrapper.header().wrapper().unwrap().fee.token,
            &shell.state,
        )
        .unwrap();

        let signer_balance = namada_sdk::token::read_balance(
            &shell.state,
            &shell.state.in_mem().native_token,
            &wrapper.header().wrapper().unwrap().fee_payer(),
        )
        .unwrap();

        let processed_tx = ProcessedTx {
            tx: wrapper.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        };

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                proposer_address,
                ..Default::default()
            })
            .expect("Test failed")[0];

        // Check fee payment
        assert_eq!(*event.kind(), APPLIED_TX);
        let code = event.read_attribute::<CodeAttr>().expect("Test failed");
        assert_eq!(code, ResultCode::Ok);

        let new_proposer_balance = namada_sdk::token::read_balance(
            &shell.state,
            &shell.state.in_mem().native_token,
            &validator,
        )
        .unwrap();
        assert_eq!(
            new_proposer_balance,
            proposer_balance.checked_add(fee_amount).unwrap()
        );

        let new_signer_balance = namada_sdk::token::read_balance(
            &shell.state,
            &shell.state.in_mem().native_token,
            &wrapper.header().wrapper().unwrap().fee_payer(),
        )
        .unwrap();
        assert_eq!(
            new_signer_balance,
            signer_balance.checked_sub(fee_amount).unwrap()
        )
    }

    #[test]
    fn test_ledger_slashing() -> namada_sdk::state::Result<()> {
        let num_validators = 7_u64;
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators,
            ..Default::default()
        });
        let mut params = read_pos_params(&shell.state).unwrap();
        params.owned.unbonding_len = 4;
        write_pos_params(&mut shell.state, &params.owned)?;

        let validator_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let val1 = validator_set[0].clone();
        let val2 = validator_set[1].clone();

        let initial_stake = val1.bonded_stake;
        let total_initial_stake = num_validators * initial_stake;

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.state, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            let vec = HEXUPPER.decode(hash_string.as_bytes()).unwrap();
            let res: [u8; 20] = TryFrom::try_from(vec).unwrap();
            res
        };

        let mut all_pkhs: Vec<[u8; 20]> = Vec::new();
        let mut behaving_pkhs: Vec<[u8; 20]> = Vec::new();
        for (idx, validator) in validator_set.iter().enumerate() {
            // Every validator should be in the consensus set
            assert_eq!(
                validator_state_handle(&validator.address)
                    .get(&shell.state, Epoch::default(), &params)
                    .unwrap(),
                Some(ValidatorState::Consensus)
            );
            all_pkhs.push(get_pkh(validator.address.clone(), Epoch::default()));
            if idx > 1_usize {
                behaving_pkhs
                    .push(get_pkh(validator.address.clone(), Epoch::default()));
            }
        }

        let pkh1 = all_pkhs[0];
        let pkh2 = all_pkhs[1];

        // Finalize block 1 (no votes since this is the first block)
        next_block_for_inflation(&mut shell, pkh1.to_vec(), vec![], None);

        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        assert!(!votes.is_empty());
        assert_eq!(votes.len(), 7_usize);

        // For block 2, include the evidences found for block 1.
        // NOTE: Only the type, height, and validator address fields from the
        // Misbehavior struct are used in Namada
        let byzantine_validators = vec![
            Misbehavior {
                kind: MisbehaviorKind::DuplicateVote,
                validator: Validator {
                    address: pkh1,
                    power: Default::default(),
                },
                height: 1_u32.into(),
                time: tendermint::Time::unix_epoch(),
                total_voting_power: Default::default(),
            },
            Misbehavior {
                kind: MisbehaviorKind::LightClientAttack,
                validator: Validator {
                    address: pkh2,
                    power: Default::default(),
                },
                height: 2_u32.into(),
                time: tendermint::Time::unix_epoch(),
                total_voting_power: Default::default(),
            },
        ];
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes,
            Some(byzantine_validators),
        );

        let processing_epoch = shell.state.in_mem().block.epoch
            + params.unbonding_len
            + 1_u64
            + params.cubic_slashing_window_length;

        // Check that the ValidatorState, enqueued slashes, and validator sets
        // are properly updated
        assert_eq!(
            validator_state_handle(&val1.address)
                .get(&shell.state, Epoch::default(), &params)
                .unwrap(),
            Some(ValidatorState::Consensus)
        );
        assert_eq!(
            validator_state_handle(&val2.address)
                .get(&shell.state, Epoch::default(), &params)
                .unwrap(),
            Some(ValidatorState::Consensus)
        );
        assert!(
            enqueued_slashes_handle()
                .at(&Epoch::default())
                .is_empty(&shell.state)?
        );
        assert_eq!(
            get_num_consensus_validators(&shell.state, Epoch::default())
                .unwrap(),
            7_u64
        );
        for epoch in Epoch::default().next().iter_range(params.pipeline_len) {
            assert_eq!(
                validator_state_handle(&val1.address)
                    .get(&shell.state, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert_eq!(
                validator_state_handle(&val2.address)
                    .get(&shell.state, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert!(
                enqueued_slashes_handle()
                    .at(&epoch)
                    .is_empty(&shell.state)?
            );
            assert_eq!(
                get_num_consensus_validators(&shell.state, epoch).unwrap(),
                5_u64
            );
        }
        assert!(
            !enqueued_slashes_handle()
                .at(&processing_epoch)
                .is_empty(&shell.state)?
        );

        // Advance to the processing epoch
        loop {
            let votes = get_default_true_votes(
                &shell.state,
                shell.state.in_mem().block.epoch,
            );
            next_block_for_inflation(
                &mut shell,
                pkh1.to_vec(),
                votes.clone(),
                None,
            );
            // println!(
            //     "Block {} epoch {}",
            //     shell.state.in_mem().block.height,
            //     shell.state.in_mem().block.epoch
            // );
            if shell.state.in_mem().block.epoch == processing_epoch {
                // println!("Reached processing epoch");
                break;
            } else {
                assert!(
                    enqueued_slashes_handle()
                        .at(&shell.state.in_mem().block.epoch)
                        .is_empty(&shell.state)?
                );
                let stake1 = read_validator_stake(
                    &shell.state,
                    &params,
                    &val1.address,
                    shell.state.in_mem().block.epoch,
                )?;
                let stake2 = read_validator_stake(
                    &shell.state,
                    &params,
                    &val2.address,
                    shell.state.in_mem().block.epoch,
                )?;
                let total_stake = read_total_stake(
                    &shell.state,
                    &params,
                    shell.state.in_mem().block.epoch,
                )?;
                assert_eq!(stake1, initial_stake);
                assert_eq!(stake2, initial_stake);
                assert_eq!(total_stake, total_initial_stake);
            }
        }

        let num_slashes = namada_sdk::state::iter_prefix_bytes(
            &shell.state,
            slashes_prefix(),
        )?
        .filter(|kv_res| {
            let (k, _v) = kv_res.as_ref().unwrap();
            is_validator_slashes_key(k).is_some()
        })
        .count();

        assert_eq!(num_slashes, 2);
        assert_eq!(
            validator_slashes_handle(&val1.address)
                .len(&shell.state)
                .unwrap(),
            1_u64
        );
        assert_eq!(
            validator_slashes_handle(&val2.address)
                .len(&shell.state)
                .unwrap(),
            1_u64
        );

        let slash1 = validator_slashes_handle(&val1.address)
            .get(&shell.state, 0)?
            .unwrap();
        let slash2 = validator_slashes_handle(&val2.address)
            .get(&shell.state, 0)?
            .unwrap();

        assert_eq!(slash1.r#type, SlashType::DuplicateVote);
        assert_eq!(slash2.r#type, SlashType::LightClientAttack);
        assert_eq!(slash1.epoch, Epoch::default());
        assert_eq!(slash2.epoch, Epoch::default());

        // Each validator has equal weight in this test, and two have been
        // slashed
        let frac = Dec::two() / Dec::new(7, 0).unwrap();
        let cubic_rate = Dec::new(9, 0).unwrap() * frac * frac;

        assert_eq!(slash1.rate, cubic_rate);
        assert_eq!(slash2.rate, cubic_rate);

        // Check that there are still 5 consensus validators and the 2
        // misbehaving ones are still jailed
        for epoch in shell
            .state
            .in_mem()
            .block
            .epoch
            .iter_range(params.pipeline_len + 1)
        {
            assert_eq!(
                validator_state_handle(&val1.address)
                    .get(&shell.state, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert_eq!(
                validator_state_handle(&val2.address)
                    .get(&shell.state, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert_eq!(
                get_num_consensus_validators(&shell.state, epoch).unwrap(),
                5_u64
            );
        }

        // Check that the deltas at the pipeline epoch are slashed
        let pipeline_epoch =
            shell.state.in_mem().block.epoch + params.pipeline_len;
        let stake1 = read_validator_stake(
            &shell.state,
            &params,
            &val1.address,
            pipeline_epoch,
        )?;
        let stake2 = read_validator_stake(
            &shell.state,
            &params,
            &val2.address,
            pipeline_epoch,
        )?;
        let total_stake =
            read_total_stake(&shell.state, &params, pipeline_epoch)?;

        let expected_slashed = initial_stake.mul_ceil(cubic_rate).unwrap();

        println!(
            "Initial stake = {}\nCubic rate = {}\nExpected slashed = {}\n",
            initial_stake.to_string_native(),
            cubic_rate,
            expected_slashed.to_string_native()
        );

        assert!(
            (stake1.change() - (initial_stake - expected_slashed).change())
                .abs()
                <= 1.into()
        );
        assert!(
            (stake2.change() - (initial_stake - expected_slashed).change())
                .abs()
                <= 1.into()
        );
        assert_eq!(total_stake, total_initial_stake - 2u64 * expected_slashed);

        // Unjail one of the validators
        let current_epoch = shell.state.in_mem().block.epoch;
        unjail_validator::<_, governance::Store<_>>(
            &mut shell.state,
            &val1.address,
            current_epoch,
        )?;
        let pipeline_epoch = current_epoch + params.pipeline_len;

        // Check that the state is the same until the pipeline epoch, at which
        // point one validator is unjailed
        for epoch in shell
            .state
            .in_mem()
            .block
            .epoch
            .iter_range(params.pipeline_len)
        {
            assert_eq!(
                validator_state_handle(&val1.address)
                    .get(&shell.state, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert_eq!(
                validator_state_handle(&val2.address)
                    .get(&shell.state, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert_eq!(
                get_num_consensus_validators(&shell.state, epoch).unwrap(),
                5_u64
            );
        }
        assert_eq!(
            validator_state_handle(&val1.address)
                .get(&shell.state, pipeline_epoch, &params)
                .unwrap(),
            Some(ValidatorState::Consensus)
        );
        assert_eq!(
            validator_state_handle(&val2.address)
                .get(&shell.state, pipeline_epoch, &params)
                .unwrap(),
            Some(ValidatorState::Jailed)
        );
        assert_eq!(
            get_num_consensus_validators(&shell.state, pipeline_epoch).unwrap(),
            6_u64
        );

        Ok(())
    }

    /// NOTE: must call `get_default_true_votes` before every call to
    /// `next_block_for_inflation`
    #[test]
    fn test_multiple_misbehaviors() -> namada_sdk::state::Result<()> {
        for num_validators in &[4_u64, 6_u64, 9_u64] {
            tracing::debug!("\nNUM VALIDATORS = {}", num_validators);
            test_multiple_misbehaviors_by_num_vals(*num_validators)?;
        }
        Ok(())
    }

    /// Current test procedure (prefixed by epoch in which the event occurs):
    /// 0) Validator initial stake of 00_000
    /// 1) Delegate 37_231 to validator
    /// 1) Self-unbond 84_654
    /// 2) Unbond delegation of 18_000
    /// 3) Self-bond 9_123
    /// 4) Self-unbond 15_000
    /// 5) Delegate 8_144 to validator
    /// 6) Discover misbehavior in epoch 3
    /// 7) Discover misbehavior in epoch 4
    fn test_multiple_misbehaviors_by_num_vals(
        num_validators: u64,
    ) -> namada_sdk::state::Result<()> {
        // Setup the network with pipeline_len = 2, unbonding_len = 4
        // let num_validators = 8_u64;
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators,
            ..Default::default()
        });
        let mut params = read_pos_params(&shell.state).unwrap();
        params.owned.unbonding_len = 4;
        params.owned.max_validator_slots = 50;
        write_pos_params(&mut shell.state, &params.owned)?;

        // Slash pool balance
        let nam_address = shell.state.in_mem().native_token.clone();
        let slash_pool_balance_init = read_balance(
            &shell.state,
            &nam_address,
            &proof_of_stake::SLASH_POOL_ADDRESS,
        )
        .unwrap();
        debug_assert_eq!(slash_pool_balance_init, token::Amount::zero());

        let consensus_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let val1 = consensus_set[0].clone();
        let pkh1 = get_pkh_from_address(
            &shell.state,
            &params,
            val1.address.clone(),
            Epoch::default(),
        );

        let initial_stake = val1.bonded_stake;
        let total_initial_stake = num_validators * initial_stake;

        // Finalize block 1
        next_block_for_inflation(&mut shell, pkh1.to_vec(), vec![], None);

        let votes = get_default_true_votes(&shell.state, Epoch::default());
        assert!(!votes.is_empty());

        // Advance to epoch 1 and
        // 1. Delegate 67231 NAM to validator
        // 2. Validator self-unbond 154654 NAM
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(shell.state.in_mem().block.epoch.0, 1_u64);

        // Make an account with balance and delegate some tokens
        let delegator = address::testing::gen_implicit_address();
        let del_1_amount = token::Amount::native_whole(37_231);
        let staking_token = shell.state.in_mem().native_token.clone();
        namada_sdk::token::credit_tokens(
            &mut shell.state,
            &staking_token,
            &delegator,
            token::Amount::native_whole(200_000),
        )
        .unwrap();
        bond_tokens::<_, governance::Store<_>, token::Store<_>>(
            &mut shell.state,
            Some(&delegator),
            &val1.address,
            del_1_amount,
            current_epoch,
            None,
        )
        .unwrap();

        // Self-unbond
        let self_unbond_1_amount = token::Amount::native_whole(84_654);
        proof_of_stake::unbond_tokens::<_, governance::Store<_>>(
            &mut shell.state,
            None,
            &val1.address,
            self_unbond_1_amount,
            current_epoch,
            false,
        )
        .unwrap();

        let val_stake = proof_of_stake::storage::read_validator_stake(
            &shell.state,
            &params,
            &val1.address,
            current_epoch + params.pipeline_len,
        )
        .unwrap();

        let total_stake = proof_of_stake::storage::read_total_stake(
            &shell.state,
            &params,
            current_epoch + params.pipeline_len,
        )
        .unwrap();

        assert_eq!(
            val_stake,
            initial_stake + del_1_amount - self_unbond_1_amount
        );
        assert_eq!(
            total_stake,
            total_initial_stake + del_1_amount - self_unbond_1_amount
        );

        // Advance to epoch 2 and
        // 1. Unbond 18000 NAM from delegation
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        tracing::debug!("\nUnbonding in epoch 2");
        let del_unbond_1_amount = token::Amount::native_whole(18_000);
        proof_of_stake::unbond_tokens::<_, governance::Store<_>>(
            &mut shell.state,
            Some(&delegator),
            &val1.address,
            del_unbond_1_amount,
            current_epoch,
            false,
        )
        .unwrap();

        let val_stake = proof_of_stake::storage::read_validator_stake(
            &shell.state,
            &params,
            &val1.address,
            current_epoch + params.pipeline_len,
        )
        .unwrap();
        let total_stake = proof_of_stake::storage::read_total_stake(
            &shell.state,
            &params,
            current_epoch + params.pipeline_len,
        )
        .unwrap();
        assert_eq!(
            val_stake,
            initial_stake + del_1_amount
                - self_unbond_1_amount
                - del_unbond_1_amount
        );
        assert_eq!(
            total_stake,
            total_initial_stake + del_1_amount
                - self_unbond_1_amount
                - del_unbond_1_amount
        );

        // Advance to epoch 3 and
        // 1. Validator self-bond 9123 NAM
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        tracing::debug!("\nBonding in epoch 3");

        let self_bond_1_amount = token::Amount::native_whole(9_123);
        bond_tokens::<_, governance::Store<_>, token::Store<_>>(
            &mut shell.state,
            None,
            &val1.address,
            self_bond_1_amount,
            current_epoch,
            None,
        )
        .unwrap();

        // Advance to epoch 4
        // 1. Validator self-unbond 15000 NAM
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 4_u64);

        let self_unbond_2_amount = token::Amount::native_whole(15_000);
        proof_of_stake::unbond_tokens::<_, governance::Store<_>>(
            &mut shell.state,
            None,
            &val1.address,
            self_unbond_2_amount,
            current_epoch,
            false,
        )
        .unwrap();

        // Advance to epoch 5 and
        // Delegate 8144 NAM to validator
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 5_u64);
        tracing::debug!("Delegating in epoch 5");

        // Delegate
        let del_2_amount = token::Amount::native_whole(8_144);
        bond_tokens::<_, governance::Store<_>, token::Store<_>>(
            &mut shell.state,
            Some(&delegator),
            &val1.address,
            del_2_amount,
            current_epoch,
            None,
        )
        .unwrap();

        tracing::debug!("Advancing to epoch 6");

        // Advance to epoch 6
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 6_u64);

        // Discover a misbehavior committed in epoch 3
        // NOTE: Only the type, height, and validator address fields from the
        // Misbehavior struct are used in Namada
        let misbehavior_epoch = Epoch(3_u64);
        let height = shell.state.in_mem().block.pred_epochs.first_block_heights
            [misbehavior_epoch.0 as usize];
        let misbehaviors = vec![Misbehavior {
            kind: MisbehaviorKind::DuplicateVote,
            validator: Validator {
                address: pkh1,
                power: Default::default(),
            },
            height: height.try_into().unwrap(),
            time: tendermint::Time::unix_epoch(),
            total_voting_power: Default::default(),
        }];
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes.clone(),
            Some(misbehaviors),
        );

        // Assertions
        assert_eq!(current_epoch.0, 6_u64);
        let processing_epoch = misbehavior_epoch
            + params.unbonding_len
            + 1_u64
            + params.cubic_slashing_window_length;
        let enqueued_slash = enqueued_slashes_handle()
            .at(&processing_epoch)
            .at(&val1.address)
            .get(&shell.state, &height.0)
            .unwrap()
            .unwrap();
        assert_eq!(enqueued_slash.epoch, misbehavior_epoch);
        assert_eq!(enqueued_slash.r#type, SlashType::DuplicateVote);
        assert_eq!(enqueued_slash.rate, Dec::zero());
        let last_slash =
            proof_of_stake::storage::read_validator_last_slash_epoch(
                &shell.state,
                &val1.address,
            )
            .unwrap();
        assert_eq!(last_slash, Some(misbehavior_epoch));
        assert!(
            proof_of_stake::storage::validator_slashes_handle(&val1.address)
                .is_empty(&shell.state)
                .unwrap()
        );

        tracing::debug!("Advancing to epoch 7");

        // Advance to epoch 7
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);

        // Discover two more misbehaviors, one committed in epoch 3, one in
        // epoch 4
        let height4 =
            shell.state.in_mem().block.pred_epochs.first_block_heights[4];
        let misbehaviors = vec![
            Misbehavior {
                kind: MisbehaviorKind::DuplicateVote,
                validator: Validator {
                    address: pkh1,
                    power: Default::default(),
                },
                height: height.next_height().try_into().unwrap(),
                time: tendermint::Time::unix_epoch(),
                total_voting_power: Default::default(),
            },
            Misbehavior {
                kind: MisbehaviorKind::DuplicateVote,
                validator: Validator {
                    address: pkh1,
                    power: Default::default(),
                },
                height: height4.try_into().unwrap(),
                time: tendermint::Time::unix_epoch(),
                total_voting_power: Default::default(),
            },
        ];
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes,
            Some(misbehaviors),
        );
        assert_eq!(current_epoch.0, 7_u64);
        let enqueued_slashes_8 = enqueued_slashes_handle()
            .at(&processing_epoch)
            .at(&val1.address);
        let enqueued_slashes_9 = enqueued_slashes_handle()
            .at(&processing_epoch.next())
            .at(&val1.address);

        let num_enqueued_8 =
            enqueued_slashes_8.iter(&shell.state).unwrap().count();
        let num_enqueued_9 =
            enqueued_slashes_9.iter(&shell.state).unwrap().count();

        assert_eq!(num_enqueued_8, 2);
        assert_eq!(num_enqueued_9, 1);
        let last_slash =
            proof_of_stake::storage::read_validator_last_slash_epoch(
                &shell.state,
                &val1.address,
            )
            .unwrap();
        assert_eq!(last_slash, Some(Epoch(4)));
        assert!(
            proof_of_stake::is_validator_frozen(
                &shell.state,
                &val1.address,
                current_epoch,
                &params
            )
            .unwrap()
        );
        assert!(
            proof_of_stake::storage::validator_slashes_handle(&val1.address)
                .is_empty(&shell.state)
                .unwrap()
        );

        let pre_stake_10 = proof_of_stake::storage::read_validator_stake(
            &shell.state,
            &params,
            &val1.address,
            Epoch(10),
        )
        .unwrap();
        assert_eq!(
            pre_stake_10,
            initial_stake + del_1_amount
                - self_unbond_1_amount
                - del_unbond_1_amount
                + self_bond_1_amount
                - self_unbond_2_amount
                + del_2_amount
        );

        tracing::debug!("\nNow processing the infractions\n");

        // Advance to epoch 9, where the infractions committed in epoch 3 will
        // be processed
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        let _ = advance_epoch(&mut shell, &pkh1, &votes, None);
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 9_u64);

        let val_stake_3 = proof_of_stake::storage::read_validator_stake(
            &shell.state,
            &params,
            &val1.address,
            Epoch(3),
        )
        .unwrap();
        let val_stake_4 = proof_of_stake::storage::read_validator_stake(
            &shell.state,
            &params,
            &val1.address,
            Epoch(4),
        )
        .unwrap();

        let tot_stake_3 = proof_of_stake::storage::read_total_stake(
            &shell.state,
            &params,
            Epoch(3),
        )
        .unwrap();
        let tot_stake_4 = proof_of_stake::storage::read_total_stake(
            &shell.state,
            &params,
            Epoch(4),
        )
        .unwrap();

        let vp_frac_3 = Dec::try_from(val_stake_3).unwrap()
            / Dec::try_from(tot_stake_3).unwrap();
        let vp_frac_4 = Dec::try_from(val_stake_4).unwrap()
            / Dec::try_from(tot_stake_4).unwrap();
        let tot_frac = Dec::two() * vp_frac_3 + vp_frac_4;
        let cubic_rate = std::cmp::min(
            Dec::one(),
            Dec::new(9, 0).unwrap() * tot_frac * tot_frac,
        );
        dbg!(cubic_rate);

        let equal_enough = |rate1: Dec, rate2: Dec| -> bool {
            let tolerance = Dec::new(1, 9).unwrap();
            rate1.abs_diff(rate2).unwrap() < tolerance
        };

        // There should be 2 slashes processed for the validator, each with rate
        // equal to the cubic slashing rate
        let val_slashes =
            proof_of_stake::storage::validator_slashes_handle(&val1.address);
        assert_eq!(val_slashes.len(&shell.state).unwrap(), 2u64);
        let is_rate_good = val_slashes
            .iter(&shell.state)
            .unwrap()
            .all(|s| equal_enough(s.unwrap().rate, cubic_rate));
        assert!(is_rate_good);

        // Check the amount of stake deducted from the futuremost epoch while
        // processing the slashes
        let post_stake_10 = read_validator_stake(
            &shell.state,
            &params,
            &val1.address,
            Epoch(10),
        )
        .unwrap();
        // The amount unbonded after the infraction that affected the deltas
        // before processing is `del_unbond_1_amount + self_bond_1_amount -
        // self_unbond_2_amount` (since this self-bond was enacted then unbonded
        // all after the infraction). Thus, the additional deltas to be
        // deducted is the (infraction stake - this) * rate
        let slash_rate_3 = std::cmp::min(Dec::one(), Dec::two() * cubic_rate);
        let exp_slashed_during_processing_9 = (initial_stake + del_1_amount
            - self_unbond_1_amount
            - del_unbond_1_amount
            + self_bond_1_amount
            - self_unbond_2_amount)
            .mul_ceil(slash_rate_3)
            .unwrap();
        assert!(
            ((pre_stake_10 - post_stake_10).change()
                - exp_slashed_during_processing_9.change())
            .abs()
                < Uint::from(1000),
            "Expected {}, got {} (with less than 1000 err)",
            exp_slashed_during_processing_9.to_string_native(),
            (pre_stake_10 - post_stake_10).to_string_native(),
        );

        // Check that we can compute the stake at the pipeline epoch
        // NOTE: may be off. by 1 namnam due to rounding;
        let exp_pipeline_stake = (Dec::one() - slash_rate_3)
            * Dec::try_from(
                initial_stake + del_1_amount
                    - self_unbond_1_amount
                    - del_unbond_1_amount
                    + self_bond_1_amount
                    - self_unbond_2_amount,
            )
            .unwrap()
            + Dec::try_from(del_2_amount).unwrap();

        assert!(
            exp_pipeline_stake
                .abs_diff(Dec::try_from(post_stake_10).unwrap())
                .unwrap()
                <= Dec::new(2, NATIVE_MAX_DECIMAL_PLACES).unwrap(),
            "Expected {}, got {} (with less than 2 err), diff {}",
            exp_pipeline_stake,
            post_stake_10.to_string_native(),
            exp_pipeline_stake
                .abs_diff(Dec::try_from(post_stake_10).unwrap())
                .unwrap(),
        );

        // Check the balance of the Slash Pool
        // TODO(namada#2984): finish once implemented
        // let slash_pool_balance: token::Amount = shell
        //     .state
        //     .read(&slash_balance_key)
        //     .expect("must be able to read")
        //     .unwrap_or_default();
        // let exp_slashed_3 = decimal_mult_amount(
        //     std::cmp::min(Decimal::TWO * cubic_rate, Decimal::ONE),
        //     val_stake_3 - del_unbond_1_amount + self_bond_1_amount
        //         - self_unbond_2_amount,
        // );
        // assert_eq!(slash_pool_balance, exp_slashed_3);

        // Advance to epoch 10, where the infraction committed in epoch 4 will
        // be processed
        let votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 10_u64);

        // Check the balance of the Slash Pool
        // TODO(namada#2984): finish once implemented
        // let slash_pool_balance: token::Amount = shell
        //     .state
        //     .read(&slash_balance_key)
        //     .expect("must be able to read")
        //     .unwrap_or_default();

        // let exp_slashed_4 = if dec!(2) * cubic_rate >= Decimal::ONE {
        //     token::Amount::zero()
        // } else if dec!(3) * cubic_rate >= Decimal::ONE {
        //     decimal_mult_amount(
        //         Decimal::ONE - dec!(2) * cubic_rate,
        //         val_stake_4 + self_bond_1_amount - self_unbond_2_amount,
        //     )
        // } else {
        //     decimal_mult_amount(
        //         std::cmp::min(cubic_rate, Decimal::ONE),
        //         val_stake_4 + self_bond_1_amount - self_unbond_2_amount,
        //     )
        // };
        // dbg!(slash_pool_balance, exp_slashed_3 + exp_slashed_4);
        // assert!(
        //     (slash_pool_balance.change()
        //         - (exp_slashed_3 + exp_slashed_4).change())
        //     .abs()
        //         <= 1
        // );

        let val_stake = read_validator_stake(
            &shell.state,
            &params,
            &val1.address,
            current_epoch + params.pipeline_len,
        )?;

        let post_stake_10 = read_validator_stake(
            &shell.state,
            &params,
            &val1.address,
            Epoch(10),
        )
        .unwrap();

        // Stake at current epoch should be equal to stake at pipeline
        assert_eq!(
            post_stake_10,
            val_stake,
            "Stake at pipeline in epoch {} ({}) expected to be equal to stake \
             in epoch 10 ({}).",
            current_epoch + params.pipeline_len,
            val_stake.to_string_native(),
            post_stake_10.to_string_native()
        );

        // dbg!(&val_stake);
        // dbg!(pre_stake_10 - post_stake_10);

        // dbg!(&exp_slashed_during_processing_9);
        // TODO(namada#2984): finish once implemented
        // assert!(
        //     ((pre_stake_11 - post_stake_11).change() -
        // exp_slashed_4.change())         .abs()
        //         <= 1
        // );

        // dbg!(&val_stake, &exp_stake);
        // dbg!(exp_slashed_during_processing_8 +
        // exp_slashed_during_processing_9); dbg!(
        //     val_stake_3
        //         - (exp_slashed_during_processing_8 +
        //           exp_slashed_during_processing_9)
        // );

        // let exp_stake = val_stake_3 - del_unbond_1_amount +
        // self_bond_1_amount
        //     - self_unbond_2_amount
        //     + del_2_amount
        //     - exp_slashed_3
        //     - exp_slashed_4;

        // assert!((exp_stake.change() - post_stake_11.change()).abs() <= 1);

        for _ in 0..2 {
            let votes = get_default_true_votes(
                &shell.state,
                shell.state.in_mem().block.epoch,
            );
            let _ = advance_epoch(&mut shell, &pkh1, &votes, None);
        }
        let current_epoch = shell.state.in_mem().block.epoch;
        assert_eq!(current_epoch.0, 12_u64);

        tracing::debug!("\nCHECK BOND AND UNBOND DETAILS");
        let details = proof_of_stake::queries::bonds_and_unbonds::<
            _,
            governance::Store<_>,
        >(&shell.state, None, None)
        .unwrap();

        let del_id = BondId {
            source: delegator.clone(),
            validator: val1.address.clone(),
        };
        let self_id = BondId {
            source: val1.address.clone(),
            validator: val1.address.clone(),
        };

        let del_details = details.get(&del_id).unwrap();
        let self_details = details.get(&self_id).unwrap();
        // dbg!(del_details, self_details);

        // Check slashes
        assert_eq!(del_details.slashes, self_details.slashes);
        assert_eq!(del_details.slashes.len(), 3);
        assert_eq!(del_details.slashes[0].epoch, Epoch(3));
        assert!(equal_enough(del_details.slashes[0].rate, cubic_rate));
        assert_eq!(del_details.slashes[1].epoch, Epoch(3));
        assert!(equal_enough(del_details.slashes[1].rate, cubic_rate));
        assert_eq!(del_details.slashes[2].epoch, Epoch(4));
        assert!(equal_enough(del_details.slashes[2].rate, cubic_rate));

        // Check delegations
        assert_eq!(del_details.bonds.len(), 2);
        assert_eq!(del_details.bonds[0].start, Epoch(3));
        assert_eq!(
            del_details.bonds[0].amount,
            del_1_amount - del_unbond_1_amount
        );
        assert!(
            (del_details.bonds[0].slashed_amount.unwrap().change()
                - std::cmp::min(
                    Dec::one(),
                    Dec::new(3, 0).unwrap() * cubic_rate
                ) * (del_1_amount.change() - del_unbond_1_amount.change()))
            .abs()
                <= Uint::from(2)
        );
        assert_eq!(del_details.bonds[1].start, Epoch(7));
        assert_eq!(del_details.bonds[1].amount, del_2_amount);
        assert_eq!(del_details.bonds[1].slashed_amount, None);

        // Check self-bonds
        assert_eq!(self_details.bonds.len(), 1);
        assert_eq!(self_details.bonds[0].start, Epoch(0));
        assert_eq!(
            self_details.bonds[0].amount,
            initial_stake - self_unbond_1_amount + self_bond_1_amount
                - self_unbond_2_amount
        );
        assert!(
            (self_details.bonds[0].slashed_amount.unwrap().change()
                - (std::cmp::min(
                    Dec::one(),
                    Dec::new(3, 0).unwrap() * cubic_rate
                ) * (initial_stake - self_unbond_1_amount
                    + self_bond_1_amount
                    - self_unbond_2_amount))
                    .change())
                <= Amount::from_uint(1000, NATIVE_MAX_DECIMAL_PLACES)
                    .unwrap()
                    .change()
        );

        // Check delegation unbonds
        assert_eq!(del_details.unbonds.len(), 1);
        assert_eq!(del_details.unbonds[0].start, Epoch(3));
        assert_eq!(del_details.unbonds[0].withdraw, Epoch(9));
        assert_eq!(del_details.unbonds[0].amount, del_unbond_1_amount);
        assert!(
            (del_details.unbonds[0].slashed_amount.unwrap().change()
                - (std::cmp::min(Dec::one(), Dec::two() * cubic_rate)
                    * del_unbond_1_amount)
                    .change())
            .abs()
                <= Uint::from(1)
        );

        // Check self-unbonds
        assert_eq!(self_details.unbonds.len(), 3);
        assert_eq!(self_details.unbonds[0].start, Epoch(0));
        assert_eq!(self_details.unbonds[0].withdraw, Epoch(8));
        assert_eq!(self_details.unbonds[1].start, Epoch(0));
        assert_eq!(self_details.unbonds[1].withdraw, Epoch(11));
        assert_eq!(self_details.unbonds[2].start, Epoch(5));
        assert_eq!(self_details.unbonds[2].withdraw, Epoch(11));
        assert_eq!(self_details.unbonds[0].amount, self_unbond_1_amount);
        assert_eq!(self_details.unbonds[0].slashed_amount, None);
        assert_eq!(
            self_details.unbonds[1].amount,
            self_unbond_2_amount - self_bond_1_amount
        );
        let rate =
            std::cmp::min(Dec::one(), Dec::new(3, 0).unwrap() * cubic_rate);
        assert!(
            // at most off by 1
            (self_details.unbonds[1].slashed_amount.unwrap().change()
                - (self_unbond_2_amount - self_bond_1_amount)
                    .mul_ceil(rate)
                    .unwrap()
                    .change())
            .abs()
                <= Uint::from(1)
        );
        assert_eq!(self_details.unbonds[2].amount, self_bond_1_amount);
        assert_eq!(self_details.unbonds[2].slashed_amount, None);

        tracing::debug!("\nWITHDRAWING DELEGATION UNBOND");
        // let slash_pool_balance_pre_withdraw = slash_pool_balance;
        // Withdraw the delegation unbonds, which total to 18_000. This should
        // only be affected by the slashes in epoch 3
        let del_withdraw = proof_of_stake::withdraw_tokens::<
            _,
            governance::Store<_>,
            token::Store<_>,
        >(
            &mut shell.state,
            Some(&delegator),
            &val1.address,
            current_epoch,
        )
        .unwrap();

        let exp_del_withdraw_slashed_amount =
            del_unbond_1_amount.mul_ceil(slash_rate_3).unwrap();
        assert!(
            (del_withdraw
                - (del_unbond_1_amount - exp_del_withdraw_slashed_amount))
                .raw_amount()
                <= Uint::one()
        );

        // TODO(namada#2984): finish once implemented
        // Check the balance of the Slash Pool
        // let slash_pool_balance: token::Amount = shell
        //     .state
        //     .read(&slash_balance_key)
        //     .expect("must be able to read")
        //     .unwrap_or_default();
        // dbg!(del_withdraw, slash_pool_balance);
        // assert_eq!(
        //     slash_pool_balance - slash_pool_balance_pre_withdraw,
        //     exp_del_withdraw_slashed_amount
        // );

        // println!("\nWITHDRAWING SELF UNBOND");
        // Withdraw the self unbonds, which total 154_654 + 15_000 - 9_123. Only
        // the (15_000 - 9_123) tokens are slashable.
        // let self_withdraw = proof_of_stake::withdraw_tokens(
        //     &mut shell.state,
        //     None,
        //     &val1.address,
        //     current_epoch,
        // )
        // .unwrap();

        // let exp_self_withdraw_slashed_amount = decimal_mult_amount(
        //     std::cmp::min(dec!(3) * cubic_rate, Decimal::ONE),
        //     self_unbond_2_amount - self_bond_1_amount,
        // );
        // Check the balance of the Slash Pool
        // let slash_pool_balance: token::Amount = shell
        //     .state
        //     .read(&slash_balance_key)
        //     .expect("must be able to read")
        //     .unwrap_or_default();

        // dbg!(self_withdraw, slash_pool_balance);
        // dbg!(
        //     decimal_mult_amount(dec!(2) * cubic_rate, val_stake_3)
        //         + decimal_mult_amount(cubic_rate, val_stake_4)
        // );

        // assert_eq!(
        //     exp_self_withdraw_slashed_amount,
        //     slash_pool_balance
        //         - slash_pool_balance_pre_withdraw
        //         - exp_del_withdraw_slashed_amount
        // );

        Ok(())
    }

    #[test]
    fn test_jail_validator_for_inactivity() -> namada_sdk::state::Result<()> {
        let num_validators = 5_u64;
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators,
            ..Default::default()
        });
        let params = read_pos_params(&shell.state).unwrap();

        let initial_consensus_set: Vec<Address> =
            read_consensus_validator_set_addresses(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();
        let val1 = initial_consensus_set[0].clone();
        let pkh1 = get_pkh_from_address(
            &shell.state,
            &params,
            val1.clone(),
            Epoch::default(),
        );
        let val2 = initial_consensus_set[1].clone();
        let pkh2 = get_pkh_from_address(
            &shell.state,
            &params,
            val2.clone(),
            Epoch::default(),
        );

        let validator_stake = proof_of_stake::storage::read_validator_stake(
            &shell.state,
            &params,
            &val2,
            Epoch::default(),
        )
        .unwrap();

        let val3 = initial_consensus_set[2].clone();
        let val4 = initial_consensus_set[3].clone();
        let val5 = initial_consensus_set[4].clone();

        // Finalize block 1
        next_block_for_inflation(&mut shell, pkh1.to_vec(), vec![], None);

        // Ensure that there is no liveness data yet since there were no votes
        let missed_votes = liveness_missed_votes_handle();
        let sum_missed_votes = liveness_sum_missed_votes_handle();
        assert!(missed_votes.is_empty(&shell.state)?);
        assert!(sum_missed_votes.is_empty(&shell.state)?);

        let minimum_unsigned_blocks = ((Dec::one()
            - params.liveness_threshold)
            * params.liveness_window_check)
            .to_uint()
            .unwrap()
            .as_u64();

        // Finalize block 2 and ensure that some data has been written
        let default_all_votes = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            default_all_votes.clone(),
            None,
        );
        assert!(missed_votes.is_empty(&shell.state)?);
        for val in &initial_consensus_set {
            let sum = sum_missed_votes.get(&shell.state, val)?;
            assert_eq!(sum, Some(0u64));
        }

        // Completely unbond one of the validator to test the pruning at the
        // pipeline epoch
        let mut current_epoch = shell.state.in_mem().block.epoch;
        proof_of_stake::unbond_tokens::<_, governance::Store<_>>(
            &mut shell.state,
            None,
            &val5,
            validator_stake,
            current_epoch,
            false,
        )?;
        let pipeline_vals = read_consensus_validator_set_addresses(
            &shell.state,
            current_epoch + params.pipeline_len,
        )?;
        assert_eq!(pipeline_vals.len(), initial_consensus_set.len() - 1);
        let val5_pipeline_state = validator_state_handle(&val5)
            .get(&shell.state, current_epoch + params.pipeline_len, &params)?
            .unwrap();
        assert_eq!(val5_pipeline_state, ValidatorState::BelowThreshold);

        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            default_all_votes,
            None,
        );

        // Advance to the next epoch with no votes from validator 2
        // NOTE: assume the minimum blocks for jailing is larger than remaining
        // blocks to next epoch!
        let mut votes_no2 = get_default_true_votes(
            &shell.state,
            shell.state.in_mem().block.epoch,
        );
        votes_no2.retain(|vote| vote.validator.address != pkh2);

        let first_height_without_vote = 3;
        let mut val2_num_missed_blocks = 0u64;
        while current_epoch == Epoch::default() {
            next_block_for_inflation(
                &mut shell,
                pkh1.to_vec(),
                votes_no2.clone(),
                None,
            );
            current_epoch = shell.state.in_mem().block.epoch;
            val2_num_missed_blocks += 1;
        }

        // Checks upon the new epoch
        for val in &initial_consensus_set {
            let missed_votes = liveness_missed_votes_handle().at(val);
            let sum = sum_missed_votes.get(&shell.state, val)?;

            if val == &val2 {
                assert_eq!(sum, Some(val2_num_missed_blocks));
                for height in first_height_without_vote
                    ..first_height_without_vote + val2_num_missed_blocks
                {
                    assert!(missed_votes.contains(&shell.state, &height)?);
                    assert!(sum.unwrap() < minimum_unsigned_blocks);
                }
            } else {
                assert!(missed_votes.is_empty(&shell.state)?);
                assert_eq!(sum, Some(0u64));
            }
        }

        // Advance blocks up to just before the next epoch
        loop {
            next_block_for_inflation(
                &mut shell,
                pkh1.to_vec(),
                votes_no2.clone(),
                None,
            );
            if shell.state.in_mem().update_epoch_blocks_delay == Some(1) {
                break;
            }
        }
        assert_eq!(shell.state.in_mem().block.epoch, current_epoch);
        let pipeline_vals = read_consensus_validator_set_addresses(
            &shell.state,
            current_epoch + params.pipeline_len,
        )?;
        assert_eq!(pipeline_vals.len(), initial_consensus_set.len() - 1);
        let val2_sum_missed_votes =
            liveness_sum_missed_votes_handle().get(&shell.state, &val2)?;
        assert_eq!(
            val2_sum_missed_votes,
            Some(
                shell.state.in_mem().block.height.0 - first_height_without_vote
            )
        );
        for val in &initial_consensus_set {
            if val == &val2 {
                continue;
            }
            let sum = sum_missed_votes.get(&shell.state, val)?;
            assert_eq!(sum, Some(0u64));
        }

        // Now advance one more block to the next epoch, where validator 2 will
        // miss its 10th vote and should thus be jailed for liveness
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes_no2.clone(),
            None,
        );
        current_epoch = shell.state.in_mem().block.epoch;
        assert_eq!(current_epoch, Epoch(2));

        let val2_sum_missed_votes =
            liveness_sum_missed_votes_handle().get(&shell.state, &val2)?;
        assert_eq!(val2_sum_missed_votes, Some(minimum_unsigned_blocks));

        // Check the validator sets for all epochs up through the pipeline
        let consensus_vals = read_consensus_validator_set_addresses(
            &shell.state,
            current_epoch,
        )?;
        assert_eq!(
            consensus_vals,
            [val1.clone(), val2.clone(), val3.clone(), val4.clone()]
                .into_iter()
                .collect::<HashSet<_>>(),
        );
        for offset in 1..=params.pipeline_len {
            let consensus_vals = read_consensus_validator_set_addresses(
                &shell.state,
                current_epoch + offset,
            )?;
            assert_eq!(
                consensus_vals,
                [val1.clone(), val3.clone(), val4.clone()]
                    .into_iter()
                    .collect::<HashSet<_>>()
            );
            let val2_state = validator_state_handle(&val2)
                .get(&shell.state, current_epoch + offset, &params)?
                .unwrap();
            assert_eq!(val2_state, ValidatorState::Jailed);
            let val5_state = validator_state_handle(&val5)
                .get(&shell.state, current_epoch + offset, &params)?
                .unwrap();
            assert_eq!(val5_state, ValidatorState::BelowThreshold);
        }

        // Check the liveness data for validators 2 and 5 (2 should still be
        // there, 5 should be removed)
        for val in &initial_consensus_set {
            let missed_votes = liveness_missed_votes_handle().at(val);
            let sum = sum_missed_votes.get(&shell.state, val)?;

            if val == &val2 {
                assert_eq!(
                    sum,
                    Some(
                        shell.state.in_mem().block.height.0
                            - first_height_without_vote
                    )
                );
                for height in first_height_without_vote
                    ..shell.state.in_mem().block.height.0
                {
                    assert!(missed_votes.contains(&shell.state, &height)?);
                }
            } else if val == &val5 {
                assert!(missed_votes.is_empty(&shell.state)?);
                assert!(sum.is_none());
            } else {
                assert!(missed_votes.is_empty(&shell.state)?);
                assert_eq!(sum, Some(0u64));
            }
        }

        // Advance to the next epoch to ensure that the val2 data is removed
        // from the liveness data
        let next_epoch = current_epoch.next();
        loop {
            let votes = get_default_true_votes(
                &shell.state,
                shell.state.in_mem().block.epoch,
            );
            current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None).0;
            if current_epoch == next_epoch {
                break;
            }
        }

        // Check that the liveness data only contains data for vals 1, 3, and 4
        for val in &initial_consensus_set {
            let missed_votes = liveness_missed_votes_handle().at(val);
            let sum = sum_missed_votes.get(&shell.state, val)?;

            assert!(missed_votes.is_empty(&shell.state)?);
            if val == &val2 || val == &val5 {
                assert!(sum.is_none());
            } else {
                assert_eq!(sum, Some(0u64));
            }
        }

        // Validator 2 unjail itself
        proof_of_stake::unjail_validator::<_, governance::Store<_>>(
            &mut shell.state,
            &val2,
            current_epoch,
        )?;
        let pipeline_epoch = current_epoch + params.pipeline_len;
        let val2_pipeline_state = validator_state_handle(&val2).get(
            &shell.state,
            pipeline_epoch,
            &params,
        )?;
        assert_eq!(val2_pipeline_state, Some(ValidatorState::Consensus));

        // Advance to the pipeline epoch
        loop {
            let votes = get_default_true_votes(
                &shell.state,
                shell.state.in_mem().block.epoch,
            );
            current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None).0;
            if current_epoch == pipeline_epoch {
                break;
            }
        }
        let sum_liveness = liveness_sum_missed_votes_handle();
        assert_eq!(sum_liveness.get(&shell.state, &val1)?, Some(0u64));
        assert_eq!(sum_liveness.get(&shell.state, &val2)?, None);
        assert_eq!(sum_liveness.get(&shell.state, &val3)?, Some(0u64));
        assert_eq!(sum_liveness.get(&shell.state, &val4)?, Some(0u64));
        assert_eq!(sum_liveness.get(&shell.state, &val5)?, None);

        Ok(())
    }

    fn get_default_true_votes<S>(storage: &S, epoch: Epoch) -> Vec<VoteInfo>
    where
        S: StorageRead,
    {
        let params = read_pos_params(storage).unwrap();
        read_consensus_validator_set_addresses_with_stake(storage, epoch)
            .unwrap()
            .into_iter()
            .map(|val| {
                let pkh = get_pkh_from_address(
                    storage,
                    &params,
                    val.address.clone(),
                    epoch,
                );
                VoteInfo {
                    validator: Validator {
                        address: pkh,
                        power: (u128::try_from(val.bonded_stake).unwrap() as u64).try_into().unwrap(),
                    },
                    sig_info: tendermint::abci::types::BlockSignatureInfo::LegacySigned,
                }
            })
            .collect::<Vec<_>>()
    }

    fn advance_epoch(
        shell: &mut TestShell,
        proposer_address: &[u8],
        consensus_votes: &[VoteInfo],
        misbehaviors: Option<Vec<Misbehavior>>,
    ) -> (Epoch, token::Amount) {
        let current_epoch = shell.state.in_mem().block.epoch;
        let staking_token = proof_of_stake::staking_token_address(&shell.state);

        // NOTE: assumed that the only change in pos address balance by
        // advancing to the next epoch is minted inflation - no change occurs
        // due to slashing
        let pos_balance_pre =
            read_balance(&shell.state, &staking_token, &pos_address).unwrap();
        loop {
            next_block_for_inflation(
                shell,
                proposer_address.to_owned(),
                consensus_votes.to_owned(),
                misbehaviors.clone(),
            );
            if shell.state.in_mem().block.epoch == current_epoch.next() {
                break;
            }
        }
        let pos_balance_post =
            read_balance(&shell.state, &staking_token, &pos_address).unwrap();

        (
            shell.state.in_mem().block.epoch,
            pos_balance_post - pos_balance_pre,
        )
    }

    /// Test that updating the ethereum bridge params via governance works.
    #[tokio::test]
    async fn test_eth_bridge_param_updates() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _broadcaster, _, mut control_receiver) =
            setup_at_height(3u64);
        let proposal_execution_key = get_proposal_execution_key(0);
        shell
            .state
            .write(&proposal_execution_key, 0u64)
            .expect("Test failed.");
        let mut tx = Tx::new(shell.chain_id.clone(), None);
        tx.add_code_from_hash(Hash::default(), None).add_data(0u64);
        let new_min_confirmations = MinimumConfirmations::from(unsafe {
            NonZeroU64::new_unchecked(42)
        });
        shell
            .state
            .write(&min_confirmations_key(), new_min_confirmations)
            .expect("Test failed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, get_gas_scale(&shell.state).unwrap()),
        ));
        let keys_changed = BTreeSet::from([min_confirmations_key()]);
        let verifiers = BTreeSet::default();
        let batched_tx = tx.batch_ref_first_tx().unwrap();
        let ctx = namada_vp::native_vp::Ctx::<_, _, VpEvalWasm<_, _, _>>::new(
            shell.mode.get_validator_address().expect("Test failed"),
            shell.state.read_only(),
            batched_tx.tx,
            batched_tx.cmt,
            &TxIndex(0),
            &gas_meter,
            &keys_changed,
            &verifiers,
            shell.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        );
        assert!(
            ParametersVp::validate_tx(
                &ctx,
                &batched_tx,
                &keys_changed,
                &verifiers
            )
            .is_ok()
        );

        // we advance forward to the next epoch
        let mut req = FinalizeBlock::default();
        req.header.time = {
            #[allow(clippy::disallowed_methods)]
            namada_sdk::time::DateTimeUtc::now()
        };
        let current_decision_height = shell.get_current_decision_height();
        if let Some(b) = shell.state.in_mem_mut().last_block.as_mut() {
            b.height = current_decision_height + 11;
        }
        shell.finalize_block(req).expect("Test failed");
        shell.commit();

        let consensus_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = read_pos_params(&shell.state).unwrap();
        let val1 = consensus_set[0].clone();
        let pkh1 = get_pkh_from_address(
            &shell.state,
            &params,
            val1.address.clone(),
            Epoch::default(),
        );

        let _ = control_receiver.recv().await.expect("Test failed");
        // Finalize block 2
        let votes = vec![VoteInfo {
            validator: Validator {
                address: pkh1,
                power: (u128::try_from(val1.bonded_stake).expect("Test failed")
                    as u64)
                    .try_into()
                    .unwrap(),
            },
            sig_info: tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];
        next_block_for_inflation(&mut shell, pkh1.to_vec(), votes, None);
        let Command::UpdateConfig(cmd) =
            control_receiver.recv().await.expect("Test failed");
        assert_eq!(u64::from(cmd.min_confirmations), 42);
    }

    // Test a successful tx batch containing three valid transactions
    #[test]
    fn test_successful_batch() {
        let (mut shell, _broadcaster, _, _) = setup();
        let sk = wallet::defaults::bertha_keypair();

        let (batch, processed_tx) =
            mk_tx_batch(&shell, &sk, false, false, false);

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed");

        let code = event[0].read_attribute::<CodeAttr>().unwrap();
        assert_eq!(code, ResultCode::Ok);
        let inner_tx_result = event[0].read_attribute::<Batch<'_>>().unwrap();
        let inner_results = inner_tx_result;

        for cmt in batch.commitments() {
            assert!(
                inner_results
                    .get_inner_tx_result(
                        Some(&batch.header_hash()),
                        either::Right(cmt),
                    )
                    .unwrap()
                    .clone()
                    .is_ok_and(|res| res.is_accepted())
            );
        }

        // Check storage modifications
        for key in ["random_key_1", "random_key_2", "random_key_3"] {
            assert_eq!(
                shell
                    .state
                    .read::<String>(&key.parse().unwrap())
                    .unwrap()
                    .unwrap(),
                STORAGE_VALUE
            );
        }
    }

    // Test a failing atomic batch with two successful txs and a failing one.
    // Verify that also the changes applied by the valid txs are dropped and
    // that the last transaction is never executed (batch short-circuit)
    #[test]
    fn test_failing_atomic_batch() {
        let (mut shell, _broadcaster, _, _) = setup();
        let sk = wallet::defaults::bertha_keypair();

        let (batch, processed_tx) = mk_tx_batch(&shell, &sk, true, true, false);

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed");

        let code = event[0].read_attribute::<CodeAttr>().unwrap();
        assert_eq!(code, ResultCode::WasmRuntimeError);
        let inner_tx_result = event[0].read_attribute::<Batch<'_>>().unwrap();
        let inner_results = inner_tx_result;

        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[0]),
                )
                .unwrap()
                .clone()
                .is_ok_and(|res| res.is_accepted())
        );
        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[1]),
                )
                .unwrap()
                .clone()
                .is_err()
        );
        // Assert that the last tx didn't run
        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[2]),
                )
                .is_none()
        );

        // Check storage modifications are missing
        for key in ["random_key_1", "random_key_2", "random_key_3"] {
            assert!(!shell.state.has_key(&key.parse().unwrap()).unwrap());
        }
    }

    // Test a failing non-atomic batch with two successful txs and a failing
    // one. Verify that only the changes applied by the valid txs are
    // committed
    #[test]
    fn test_failing_non_atomic_batch() {
        let (mut shell, _broadcaster, _, _) = setup();
        let sk = wallet::defaults::bertha_keypair();

        let (batch, processed_tx) =
            mk_tx_batch(&shell, &sk, false, true, false);

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed");

        let code = event[0].read_attribute::<CodeAttr>().unwrap();
        assert_eq!(code, ResultCode::Ok);
        let inner_tx_result = event[0].read_attribute::<Batch<'_>>().unwrap();
        let inner_results = inner_tx_result;

        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[0]),
                )
                .unwrap()
                .clone()
                .is_ok_and(|res| res.is_accepted())
        );
        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[1])
                )
                .unwrap()
                .clone()
                .is_err()
        );
        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[2])
                )
                .unwrap()
                .clone()
                .is_ok_and(|res| res.is_accepted())
        );

        // Check storage modifications
        assert_eq!(
            shell
                .state
                .read::<String>(&"random_key_1".parse().unwrap())
                .unwrap()
                .unwrap(),
            STORAGE_VALUE
        );
        assert!(
            !shell
                .state
                .has_key(&"random_key_2".parse().unwrap())
                .unwrap()
        );
        assert_eq!(
            shell
                .state
                .read::<String>(&"random_key_3".parse().unwrap())
                .unwrap()
                .unwrap(),
            STORAGE_VALUE
        );
    }

    // Test a gas error on the second tx of an atomic batch with three
    // successful txs. Verify that no changes are committed
    #[test]
    fn test_gas_error_atomic_batch() {
        let (mut shell, _, _, _) = setup();
        let sk = wallet::defaults::bertha_keypair();

        let (batch, processed_tx) = mk_tx_batch(&shell, &sk, true, false, true);

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed");

        let code = event[0].read_attribute::<CodeAttr>().unwrap();
        assert_eq!(code, ResultCode::WasmRuntimeError);
        let inner_tx_result = event[0].read_attribute::<Batch<'_>>().unwrap();
        let inner_results = inner_tx_result;

        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[0]),
                )
                .unwrap()
                .clone()
                .is_ok_and(|res| res.is_accepted())
        );
        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[1])
                )
                .unwrap()
                .clone()
                .is_err()
        );
        // Assert that the last tx didn't run
        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[2])
                )
                .is_none()
        );

        // Check storage modifications are missing
        for key in ["random_key_1", "random_key_2", "random_key_3"] {
            assert!(!shell.state.has_key(&key.parse().unwrap()).unwrap());
        }
    }

    // Test a gas error on the second tx of a non-atomic batch with three
    // successful txs. Verify that changes from the first tx are committed
    #[test]
    fn test_gas_error_non_atomic_batch() {
        let (mut shell, _, _, _) = setup();
        let sk = wallet::defaults::bertha_keypair();

        let (batch, processed_tx) =
            mk_tx_batch(&shell, &sk, false, false, true);

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed");

        let code = event[0].read_attribute::<CodeAttr>().unwrap();
        assert_eq!(code, ResultCode::WasmRuntimeError);
        let inner_tx_result = event[0].read_attribute::<Batch<'_>>().unwrap();
        let inner_results = inner_tx_result;

        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[0]),
                )
                .unwrap()
                .clone()
                .is_ok_and(|res| res.is_accepted())
        );
        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[1])
                )
                .unwrap()
                .clone()
                .is_err()
        );
        // Assert that the last tx didn't run
        assert!(
            inner_results
                .get_inner_tx_result(
                    Some(&batch.header_hash()),
                    either::Right(&batch.commitments()[2])
                )
                .is_none()
        );

        // Check storage modifications
        assert_eq!(
            shell
                .state
                .read::<String>(&"random_key_1".parse().unwrap())
                .unwrap()
                .unwrap(),
            STORAGE_VALUE
        );
        for key in ["random_key_2", "random_key_3"] {
            assert!(!shell.state.has_key(&key.parse().unwrap()).unwrap());
        }
    }

    #[test]
    fn test_multiple_events_from_batch_tx_all_valid() {
        let (mut shell, _, _, _) = setup();

        let sk = wallet::defaults::bertha_keypair();

        let batch_tx = {
            let mut batch =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            1.into(),
                        ),
                        token: shell.state.in_mem().native_token.clone(),
                    },
                    sk.ref_to(),
                    WRAPPER_GAS_LIMIT.into(),
                ))));
            batch.header.chain_id = shell.chain_id.clone();
            batch.header.atomic = false;

            // append first inner tx to batch
            batch
                .add_code(TestWasms::TxNoOpEvent.read_bytes(), None)
                .add_data("bing");

            // append second inner tx to batch
            batch.push_default_inner_tx();
            batch
                .add_code(TestWasms::TxNoOpEvent.read_bytes(), None)
                .add_data("bong");

            // sign the batch of txs
            batch.sign_wrapper(sk);

            batch
        };

        let processed_txs = vec![ProcessedTx {
            tx: batch_tx.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        }];

        let mut events = shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // three top level events
        assert_eq!(events.len(), 3);

        // tx events. Check that they are present and in the correct order
        // TODO(namada#3856): right now we lose events ordering in a batch
        // because of the BTreeSet we use in BatchedTxResult so we can only
        // check the presence of the events but not the order
        let mut unordered_events = vec![];
        let event = events.remove(0);
        let msg = event.read_attribute::<Log>().unwrap();
        unordered_events.push(msg.as_str());

        let event = events.remove(0);
        let msg = event.read_attribute::<Log>().unwrap();
        unordered_events.push(msg.as_str());

        assert!(unordered_events.contains(&"bing"));
        assert!(unordered_events.contains(&"bong"));

        // multiple tx results (2)
        let tx_event = events.remove(0);
        let tx_results = tx_event.read_attribute::<Batch<'_>>().unwrap();
        assert_eq!(tx_results.len(), 2);

        // all txs should have succeeded
        assert!(tx_results.are_results_successfull());
    }

    #[test]
    fn test_multiple_identical_events_from_batch_tx_all_valid() {
        const EVENT_MSG: &str = "bing";
        let (mut shell, _, _, _) = setup();

        let sk = wallet::defaults::bertha_keypair();

        let batch_tx = {
            let mut batch =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            1.into(),
                        ),
                        token: shell.state.in_mem().native_token.clone(),
                    },
                    sk.ref_to(),
                    WRAPPER_GAS_LIMIT.into(),
                ))));
            batch.header.chain_id = shell.chain_id.clone();
            batch.header.atomic = false;

            // append first inner tx to batch
            batch
                .add_code(TestWasms::TxNoOpEvent.read_bytes(), None)
                .add_data(EVENT_MSG);

            // append second inner tx to batch
            batch.push_default_inner_tx();
            batch
                .add_code(TestWasms::TxNoOpEvent.read_bytes(), None)
                .add_data(EVENT_MSG);

            // sign the batch of txs
            batch.sign_wrapper(sk);

            batch
        };

        let processed_txs = vec![ProcessedTx {
            tx: batch_tx.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        }];

        let mut events = shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // three top level events
        assert_eq!(events.len(), 3);

        // tx events. Check that they are both present even if they are
        // identical. This is important because some inner txs of a single batch
        // may correctly emit identical events and we don't want them to
        // overshadow each other which could deceive external tools like
        // indexers
        let event = events.remove(0);
        let msg = event.read_attribute::<Log>().unwrap();
        assert_eq!(&msg, EVENT_MSG);

        let event = events.remove(0);
        let msg = event.read_attribute::<Log>().unwrap();
        assert_eq!(&msg, EVENT_MSG);

        // multiple tx results (2)
        let tx_event = events.remove(0);
        let tx_results = tx_event.read_attribute::<Batch<'_>>().unwrap();
        assert_eq!(tx_results.len(), 2);

        // all txs should have succeeded
        assert!(tx_results.are_results_successfull());
    }

    #[test]
    fn test_multiple_events_from_batch_tx_one_valid_other_invalid() {
        let (mut shell, _, _, _) = setup();

        let sk = wallet::defaults::bertha_keypair();

        let batch_tx = {
            let mut batch =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            1.into(),
                        ),
                        token: shell.state.in_mem().native_token.clone(),
                    },
                    sk.ref_to(),
                    WRAPPER_GAS_LIMIT.into(),
                ))));
            batch.header.chain_id = shell.chain_id.clone();
            batch.header.atomic = false;

            // append first inner tx to batch (this one is valid)
            batch
                .add_code(TestWasms::TxNoOpEvent.read_bytes(), None)
                .add_data("bing");

            // append second inner tx to batch (this one is invalid)
            batch.push_default_inner_tx();
            batch
                .add_code(TestWasms::TxFailEvent.read_bytes(), None)
                .add_data("bong");

            batch.sign_wrapper(sk);

            batch
        };

        let processed_txs = vec![ProcessedTx {
            tx: batch_tx.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        }];

        let mut events = shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // two top level events
        assert_eq!(events.len(), 2);

        // tx events. Check the expected ones are present and in the correct
        // order
        let event = events.remove(0);
        let msg = event.read_attribute::<Log>().unwrap();
        assert_eq!(&msg, "bing");

        // multiple tx results (2)
        let tx_event = events.remove(0);
        let tx_results = tx_event.read_attribute::<Batch<'_>>().unwrap();
        assert_eq!(tx_results.len(), 2);

        // check one succeeded and the other failed
        assert!(tx_results.are_any_ok());
        assert!(tx_results.are_any_err());
    }

    #[test]
    fn test_multiple_events_from_atomic_batch_tx_one_valid_other_invalid() {
        let (mut shell, _, _, _) = setup();

        let sk = wallet::defaults::bertha_keypair();

        let batch_tx = {
            let mut batch =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            1.into(),
                        ),
                        token: shell.state.in_mem().native_token.clone(),
                    },
                    sk.ref_to(),
                    WRAPPER_GAS_LIMIT.into(),
                ))));
            batch.header.chain_id = shell.chain_id.clone();
            batch.header.atomic = true;

            // append first inner tx to batch (this one is valid)
            batch
                .add_code(TestWasms::TxNoOpEvent.read_bytes(), None)
                .add_data("bing");

            // append second inner tx to batch (this one is invalid)
            batch.push_default_inner_tx();
            batch
                .add_code(TestWasms::TxFailEvent.read_bytes(), None)
                .add_data("bong");

            batch.sign_wrapper(sk);

            batch
        };

        let processed_txs = vec![ProcessedTx {
            tx: batch_tx.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        }];

        let mut events = shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // one top level event (no tx events, only tx result)
        assert_eq!(events.len(), 1);

        // multiple tx results (2)
        let tx_event = events.remove(0);
        let tx_results = tx_event.read_attribute::<Batch<'_>>().unwrap();
        assert_eq!(tx_results.len(), 2);

        // check one succeeded and the other failed but the entire batch failed
        assert!(tx_results.are_any_ok());
        assert!(tx_results.are_any_err());
        let result_code = tx_event
            .read_attribute::<namada_sdk::tx::event::Code>()
            .unwrap();
        assert_eq!(result_code, ResultCode::WasmRuntimeError);
    }

    /// DI indirection
    pub fn read_pos_params<S>(
        storage: &S,
    ) -> namada_sdk::storage::Result<PosParams>
    where
        S: StorageRead,
    {
        proof_of_stake::storage::read_pos_params::<S, governance::Store<S>>(
            storage,
        )
    }
}
