//! The ledger's protocol
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::{Debug, Display};

use either::Either;
use eyre::{WrapErr, eyre};
use namada_sdk::address::{Address, InternalAddress};
use namada_sdk::booleans::BoolResultUnitExt;
use namada_sdk::chain::BlockHeight;
use namada_sdk::collections::HashSet;
use namada_sdk::events::EventLevel;
use namada_sdk::events::extend::{
    ComposeEvent, Height as HeightAttr, InnerTxHash as InnerTxHashAttr,
    TxHash as TxHashAttr, UserAccount,
};
use namada_sdk::gas::{self, Gas, GasMetering, TxGasMeter, VpGasMeter};
use namada_sdk::hash::Hash;
use namada_sdk::parameters::get_gas_scale;
use namada_sdk::state::{
    DB, DBIter, State, StorageHasher, StorageRead, TxWrites, WlState,
};
use namada_sdk::storage::TxIndex;
use namada_sdk::token::Amount;
use namada_sdk::token::event::{TokenEvent, TokenOperation};
use namada_sdk::token::utils::is_masp_transfer;
use namada_sdk::tx::action::{self, Read};
use namada_sdk::tx::data::protocol::{ProtocolTx, ProtocolTxType};
use namada_sdk::tx::data::{
    BatchedTxResult, TxResult, VpStatusFlags, VpsResult, WrapperTx,
    compute_inner_tx_hash,
};
use namada_sdk::tx::event::{MaspEvent, MaspEventKind, MaspTxRef};
use namada_sdk::tx::{BatchedTxRef, IndexedTx, Tx, TxCommitments};
use namada_sdk::validation::{
    EthBridgeNutVp, EthBridgePoolVp, EthBridgeVp, GovernanceVp, IbcVp, MaspVp,
    MultitokenVp, NativeVpCtx, ParametersVp, PgfVp, PosVp,
};
use namada_sdk::{governance, parameters, state, storage, token};
#[doc(inline)]
pub use namada_vm::wasm::run::GasMeterKind;
use namada_vm::wasm::{TxCache, VpCache};
use namada_vm::{self, WasmCacheAccess, wasm};
use namada_vote_ext::EthereumTxData;
use namada_vp::native_vp::NativeVp;
use namada_vp::state::ReadConversionState;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use smooth_operator::checked;
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("No inner transactions were found")]
    MissingInnerTxs,
    #[error("Missing tx section: {0}")]
    MissingSection(String),
    #[error("State error: {0}")]
    StateError(state::Error),
    #[error("Storage error: {0}")]
    Error(state::Error),
    #[error("Wrapper tx runner error: {0}")]
    WrapperRunnerError(String),
    #[error("Transaction runner error: {0}")]
    TxRunnerError(wasm::run::Error),
    #[error("{0:?}")]
    ProtocolTxError(#[from] eyre::Error),
    #[error("The atomic batch failed at inner transaction {0}")]
    FailingAtomicBatch(Hash),
    #[error("Gas error: {0}")]
    GasError(String),
    #[error("Error while processing transaction's fees: {0}")]
    FeeError(String),
    #[error("Invalid transaction section signature: {0}")]
    InvalidSectionSignature(String),
    #[error(
        "The decrypted transaction {0} has already been applied in this block"
    )]
    ReplayAttempt(Hash),
    #[error("Error executing VP for addresses: {0:?}")]
    VpRunnerError(wasm::run::Error),
    #[error("The address {0} doesn't exist")]
    MissingAddress(Address),
    #[error("Native VP error: {0}")]
    NativeVpError(state::Error),
    #[error("Access to an internal address {0:?} is forbidden")]
    AccessForbidden(InternalAddress),
}

impl Error {
    /// Determine if the error originates from an invalid transaction
    /// section signature. This is required for replay protection.
    const fn invalid_section_signature_flag(&self) -> VpStatusFlags {
        if matches!(self, Self::InvalidSectionSignature(_)) {
            VpStatusFlags::INVALID_SIGNATURE
        } else {
            VpStatusFlags::empty()
        }
    }
}

/// Shell parameters for running wasm transactions.
#[allow(missing_docs)]
#[derive(Debug)]
pub struct ShellParams<'a, S, D, H, CA>
where
    S: State<D = D, H = H> + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    pub tx_gas_meter: &'a RefCell<TxGasMeter>,
    pub state: &'a mut S,
    pub vp_wasm_cache: &'a mut VpCache<CA>,
    pub tx_wasm_cache: &'a mut TxCache<CA>,
}

impl<'a, S, D, H, CA> ShellParams<'a, S, D, H, CA>
where
    S: State<D = D, H = H> + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    /// Create a new instance of `ShellParams`
    pub fn new(
        tx_gas_meter: &'a RefCell<TxGasMeter>,
        state: &'a mut S,
        vp_wasm_cache: &'a mut VpCache<CA>,
        tx_wasm_cache: &'a mut TxCache<CA>,
    ) -> Self {
        Self {
            tx_gas_meter,
            state,
            vp_wasm_cache,
            tx_wasm_cache,
        }
    }
}

/// Result of applying a transaction
pub type Result<T> = std::result::Result<T, Error>;

/// The result of a call to [`dispatch_tx`]
pub struct DispatchError {
    /// The result of the function call
    pub error: Error,
    /// The tx result produced. It could be produced even in case of
    /// an error
    pub tx_result: Option<TxResult<Error>>,
}

impl Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl From<Error> for DispatchError {
    fn from(error: Error) -> Self {
        Self {
            error,
            tx_result: None,
        }
    }
}

/// Arguments for transactions' execution
pub enum DispatchArgs<'a, CA: 'static + WasmCacheAccess + Sync> {
    /// Protocol tx data
    Protocol(&'a ProtocolTx),
    /// Raw tx data
    Raw {
        /// The tx index
        tx_index: TxIndex,
        /// The block height
        height: BlockHeight,
        /// Hash of the header of the wrapper tx containing
        /// this raw tx
        wrapper_hash: Option<&'a Hash>,
        /// The result of the corresponding wrapper tx (missing if governance
        /// transaction)
        wrapper_tx_result: Option<TxResult<Error>>,
        /// Vp cache
        vp_wasm_cache: &'a mut VpCache<CA>,
        /// Tx cache
        tx_wasm_cache: &'a mut TxCache<CA>,
    },
    /// Wrapper tx data
    Wrapper {
        /// The wrapper header
        wrapper: &'a WrapperTx,
        /// The transaction bytes for gas accounting
        tx_bytes: &'a [u8],
        /// The tx index
        tx_index: TxIndex,
        /// The block height
        height: BlockHeight,
        /// The block proposer
        block_proposer: &'a Address,
        /// Vp cache
        vp_wasm_cache: &'a mut VpCache<CA>,
        /// Tx cache
        tx_wasm_cache: &'a mut TxCache<CA>,
    },
}

/// Dispatch a given transaction to be applied based on its type.
///
/// Some storage updates may be derived and applied natively rather than via the
/// wasm environment, in which case validity predicates will be bypassed.
pub fn dispatch_tx<'a, D, H, CA>(
    tx: &Tx,
    dispatch_args: DispatchArgs<'a, CA>,
    tx_gas_meter: &'a RefCell<TxGasMeter>,
    state: &'a mut WlState<D, H>,
) -> std::result::Result<TxResult<Error>, Box<DispatchError>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    match dispatch_args {
        DispatchArgs::Raw {
            tx_index,
            height,
            wrapper_hash,
            wrapper_tx_result,
            vp_wasm_cache,
            tx_wasm_cache,
        } => {
            if let Some(tx_result) = wrapper_tx_result {
                // Replay protection check on the batch
                let tx_hash = tx.raw_header_hash();
                if state.write_log().has_replay_protection_entry(&tx_hash) {
                    // If the same batch has already been committed in
                    // this block, skip execution and return
                    return Err(Box::new(DispatchError {
                        error: Error::ReplayAttempt(tx_hash),
                        tx_result: None,
                    }));
                }

                dispatch_inner_txs(
                    tx,
                    wrapper_hash,
                    tx_result,
                    tx_index,
                    height,
                    tx_gas_meter,
                    state,
                    vp_wasm_cache,
                    tx_wasm_cache,
                    GasMeterKind::MutGlobal,
                )
            } else {
                // Governance proposal. We don't allow tx batches in this case,
                // just take the first one
                let cmt = tx.first_commitments().ok_or_else(|| {
                    Box::new(DispatchError::from(Error::MissingInnerTxs))
                })?;
                let batched_tx_result = apply_wasm_tx(
                    wrapper_hash,
                    &tx.batch_ref_tx(cmt),
                    &tx_index,
                    ShellParams {
                        tx_gas_meter,
                        state,
                        vp_wasm_cache,
                        tx_wasm_cache,
                    },
                    GasMeterKind::MutGlobal,
                )
                .map_err(|e| Box::new(DispatchError::from(e)))?;

                Ok({
                    let mut batch_results = TxResult::new();
                    batch_results.insert_inner_tx_result(
                        wrapper_hash,
                        either::Right(cmt),
                        Ok(batched_tx_result),
                    );
                    batch_results
                })
            }
        }
        DispatchArgs::Protocol(protocol_tx) => {
            // No bundles of protocol transactions, only take the first one
            let cmt = tx.first_commitments().ok_or_else(|| {
                Box::new(DispatchError::from(Error::MissingInnerTxs))
            })?;
            let batched_tx_result =
                apply_protocol_tx(protocol_tx.tx, tx.data(cmt), state)
                    .map_err(|e| Box::new(DispatchError::from(e)))?;

            Ok({
                let mut batch_results = TxResult::new();
                batch_results.insert_inner_tx_result(
                    None,
                    either::Right(cmt),
                    Ok(batched_tx_result),
                );
                batch_results
            })
        }
        DispatchArgs::Wrapper {
            wrapper,
            tx_bytes,
            tx_index,
            height,
            block_proposer,
            vp_wasm_cache,
            tx_wasm_cache,
        } => {
            let mut shell_params = ShellParams::new(
                tx_gas_meter,
                state,
                vp_wasm_cache,
                tx_wasm_cache,
            );

            apply_wrapper_tx(
                tx,
                wrapper,
                tx_bytes,
                &tx_index,
                height,
                tx_gas_meter,
                &mut shell_params,
                Some(block_proposer),
            )
            .map_err(|e| {
                Box::new(Error::WrapperRunnerError(e.to_string()).into())
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_inner_txs<'a, S, D, H, CA>(
    tx: &Tx,
    wrapper_hash: Option<&'a Hash>,
    mut tx_result: TxResult<Error>,
    tx_index: TxIndex,
    height: BlockHeight,
    tx_gas_meter: &'a RefCell<TxGasMeter>,
    state: &'a mut S,
    vp_wasm_cache: &'a mut VpCache<CA>,
    tx_wasm_cache: &'a mut TxCache<CA>,
    gas_meter_kind: GasMeterKind,
) -> std::result::Result<TxResult<Error>, Box<DispatchError>>
where
    S: 'static
        + State<D = D, H = H>
        + Read<Err = state::Error>
        + ReadConversionState
        + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    // Extract the inner transactions of the batch that need to be executed,
    // excluding those that already ran during the handling of the wrapper tx.
    let inner_txs = tx
        .commitments()
        .iter()
        .filter(|cmt| {
            let inner_tx_hash =
                compute_inner_tx_hash(wrapper_hash, Either::Right(cmt));
            !tx_result.contains_key(&inner_tx_hash)
        })
        .collect::<HashSet<_>>()
        .into_iter();

    for cmt in inner_txs {
        let res = apply_wasm_tx(
            wrapper_hash,
            &tx.batch_ref_tx(cmt),
            &tx_index,
            ShellParams {
                tx_gas_meter,
                state,
                vp_wasm_cache,
                tx_wasm_cache,
            },
            gas_meter_kind,
        );
        println!(
            "dispatch_inner_txs gas {}",
            tx_gas_meter.borrow().transaction_gas.sub
        );
        match res {
            Err(Error::GasError(msg)) => {
                // Gas error aborts the execution of the entire batch
                tx_result.insert_inner_tx_result(
                    wrapper_hash,
                    either::Right(cmt),
                    Err(Error::GasError(msg.to_owned())),
                );
                state.write_log_mut().drop_tx();
                return Err(Box::new(DispatchError {
                    error: Error::GasError(msg.to_owned()),
                    tx_result: Some(tx_result),
                }));
            }
            Ok(mut batched_tx_result) if batched_tx_result.is_accepted() => {
                // If the transaction was a masp one generate the
                // appropriate event
                if let Some(masp_ref) = get_optional_masp_ref(
                    state,
                    cmt,
                    Either::Right(&batched_tx_result),
                )
                .map_err(|e| Box::new(DispatchError::from(e)))?
                {
                    let inner_tx_hash =
                        compute_inner_tx_hash(wrapper_hash, Either::Right(cmt));
                    batched_tx_result.events.insert(
                        MaspEvent {
                            tx_index: IndexedTx {
                                block_height: height,
                                block_index: tx_index,
                                batch_index: tx
                                    .header
                                    .batch
                                    .get_index_of(cmt)
                                    .map(|idx| {
                                        TxIndex::must_from_usize(idx).into()
                                    }),
                            },
                            kind: MaspEventKind::Transfer,
                            data: masp_ref,
                        }
                        .with(TxHashAttr(
                            // Zero hash if the wrapper is not provided
                            // (governance proposal)
                            wrapper_hash.cloned().unwrap_or_default(),
                        ))
                        .with(InnerTxHashAttr(inner_tx_hash))
                        .into(),
                    );
                }

                tx_result.insert_inner_tx_result(
                    wrapper_hash,
                    either::Right(cmt),
                    Ok(batched_tx_result),
                );

                state.write_log_mut().commit_tx_to_batch();
            }
            // Handle all the other failure cases
            res => {
                tx_result.insert_inner_tx_result(
                    wrapper_hash,
                    either::Right(cmt),
                    res,
                );

                state.write_log_mut().drop_tx();

                if tx.header.atomic {
                    // Stop the execution of an atomic batch at the
                    // first failed transaction
                    return Err(Box::new(DispatchError {
                        error: Error::FailingAtomicBatch(cmt.get_hash()),
                        tx_result: Some(tx_result),
                    }));
                }
            }
        };
    }

    Ok(tx_result)
}

/// Transaction result for masp transfer
pub struct MaspTxResult {
    tx_result: BatchedTxResult,
    masp_section_ref: MaspTxRef,
}

/// Performs the required operation on a wrapper transaction:
///  - replay protection
///  - fee payment
///  - gas accounting
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_wrapper_tx<S, D, H, CA>(
    tx: &Tx,
    wrapper: &WrapperTx,
    tx_bytes: &[u8],
    tx_index: &TxIndex,
    height: BlockHeight,
    tx_gas_meter: &RefCell<TxGasMeter>,
    shell_params: &mut ShellParams<'_, S, D, H, CA>,
    block_proposer: Option<&Address>,
) -> Result<TxResult<Error>>
where
    S: 'static
        + State<D = D, H = H>
        + Read<Err = state::Error>
        + TxWrites
        + ReadConversionState
        + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    // Write wrapper tx hash to storage
    shell_params
        .state
        .write_log_mut()
        .write_tx_hash(tx.header_hash())
        .expect("Error while writing tx hash to storage");

    // Charge or check fees, propagate any errors to prevent committing invalid
    // data
    println!("has block proposer {}", block_proposer.is_some());
    let payment_result = match block_proposer {
        Some(block_proposer) => {
            transfer_fee(shell_params, block_proposer, tx, wrapper, tx_index)?
        }
        None => check_fees(shell_params, tx, wrapper)?,
    };

    // Commit tx to the block write log even in case of subsequent errors (if
    // the fee payment failed instead, then the previous two functions must
    // have propagated an error)
    shell_params
        .state
        .write_log_mut()
        .commit_batch_and_current_tx();

    let batch_results =
        payment_result.map_or_else(TxResult::default, |mut masp_tx_result| {
            // Ok to unwrap cause if we have a batched result it means we've
            // executed the first tx in the batch
            let first_commitments = tx.first_commitments().unwrap();
            let mut batch = TxResult::default();
            // Generate Masp event if needed
            masp_tx_result.tx_result.events.insert(
                MaspEvent {
                    tx_index: IndexedTx {
                        block_height: height,
                        block_index: tx_index.to_owned(),
                        batch_index: Some(0),
                    },
                    kind: MaspEventKind::FeePayment,
                    data: masp_tx_result.masp_section_ref,
                }
                .with(TxHashAttr(tx.header_hash()))
                .with(InnerTxHashAttr(compute_inner_tx_hash(
                    tx.wrapper_hash().as_ref(),
                    Either::Right(first_commitments),
                )))
                .into(),
            );

            batch.insert_inner_tx_result(
                tx.wrapper_hash().as_ref(),
                either::Right(first_commitments),
                Ok(masp_tx_result.tx_result),
            );

            batch
        });

    println!("apply_wrapper_tx_bytes gas {}", tx_bytes.len());
    // Account for gas
    tx_gas_meter
        .borrow_mut()
        .add_wrapper_gas(tx_bytes)
        .map_err(|err| Error::GasError(err.to_string()))?;

    Ok(batch_results)
}

/// Perform the actual transfer of fees from the fee payer to the block
/// proposer. No modifications to the write log are committed or dropped in this
/// function: this logic is up to the caller.
pub fn transfer_fee<S, D, H, CA>(
    shell_params: &mut ShellParams<'_, S, D, H, CA>,
    block_proposer: &Address,
    tx: &Tx,
    wrapper: &WrapperTx,
    tx_index: &TxIndex,
) -> Result<Option<MaspTxResult>>
where
    S: 'static
        + State<D = D, H = H>
        + StorageRead
        + TxWrites
        + Read<Err = state::Error>
        + ReadConversionState
        + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    match wrapper.get_tx_fee() {
        Ok(fees) => {
            let fees = token::denom_to_amount(
                fees,
                &wrapper.fee.token,
                shell_params.state,
            )
            .map_err(Error::Error)?;

            #[cfg(not(fuzzing))]
            let balance = token::read_balance(
                shell_params.state,
                &wrapper.fee.token,
                &wrapper.fee_payer(),
            )
            .map_err(Error::Error)?;

            // Use half of the max value to make the balance check pass
            // sometimes with arbitrary fees
            #[cfg(fuzzing)]
            let balance = Amount::max().checked_div_u64(2).unwrap();

            let (post_bal, valid_batched_tx_result) = if let Some(post_bal) =
                balance.checked_sub(fees)
            {
                fee_token_transfer(
                    shell_params.state,
                    &wrapper.fee.token,
                    &wrapper.fee_payer(),
                    block_proposer,
                    fees,
                )?;

                (post_bal, None)
            } else {
                // See if the first inner transaction of the batch pays the fees
                // with a masp unshield
                match try_masp_fee_payment(shell_params, tx, tx_index) {
                    Ok(valid_batched_tx_result) => {
                        #[cfg(not(fuzzing))]
                        let balance = token::read_balance(
                            shell_params.state,
                            &wrapper.fee.token,
                            &wrapper.fee_payer(),
                        )
                        .expect("Could not read balance key from storage");
                        #[cfg(fuzzing)]
                        let balance = Amount::max().checked_div_u64(2).unwrap();

                        let post_bal = match balance.checked_sub(fees) {
                            Some(post_bal) => {
                                // This cannot fail given the checked_sub check
                                // here above
                                fee_token_transfer(
                                    shell_params.state,
                                    &wrapper.fee.token,
                                    &wrapper.fee_payer(),
                                    block_proposer,
                                    fees,
                                )?;

                                post_bal
                            }
                            None => {
                                // This shouldn't happen as it should be
                                // prevented
                                // from process_proposal.
                                tracing::error!(
                                    "Transfer of tx fee cannot be applied to \
                                     due to insufficient funds. This \
                                     shouldn't happen."
                                );
                                return Err(Error::FeeError(
                                    "Insufficient funds for fee payment"
                                        .to_string(),
                                ));
                            }
                        };

                        // Batched tx result must be returned (and considered)
                        // only if fee payment was
                        // successful
                        (post_bal, Some(valid_batched_tx_result))
                    }
                    Err(e) => {
                        // This shouldn't happen as it should be prevented by
                        // process_proposal.
                        tracing::error!(
                            "Transfer of tx fee cannot be applied because of \
                             an error: {}. This shouldn't happen.",
                            e
                        );
                        return Err(e.into());
                    }
                }
            };

            let target_post_balance = Some(
                token::read_balance(
                    shell_params.state,
                    &wrapper.fee.token,
                    block_proposer,
                )
                .map_err(Error::Error)?
                .into(),
            );

            const FEE_PAYMENT_DESCRIPTOR: std::borrow::Cow<'static, str> =
                std::borrow::Cow::Borrowed("wrapper-fee-payment");
            let current_block_height = shell_params
                .state
                .in_mem()
                .get_last_block_height()
                .next_height();
            shell_params.state.write_log_mut().emit_event(
                TokenEvent {
                    descriptor: FEE_PAYMENT_DESCRIPTOR,
                    level: EventLevel::Tx,
                    operation: TokenOperation::transfer(
                        UserAccount::Internal(wrapper.fee_payer()),
                        UserAccount::Internal(block_proposer.clone()),
                        wrapper.fee.token.clone(),
                        fees.into(),
                        post_bal.into(),
                        target_post_balance,
                    ),
                }
                .with(HeightAttr(current_block_height))
                .with(TxHashAttr(tx.header_hash())),
            );

            Ok(valid_batched_tx_result)
        }
        Err(e) => {
            // Fee overflow. This shouldn't happen as it should be prevented
            // by process_proposal.
            tracing::error!(
                "Transfer of tx fee cannot be applied to due to fee overflow. \
                 This shouldn't happen."
            );
            Err(Error::FeeError(format!("{}", e)))
        }
    }
}

/// Custom wrapper type for masp fee payment errors. The purpose of this type is
/// to prepend errors with some masp fee payment string to ensure that the
/// messages we produce are not misleading
pub struct MaspFeeError(Error);

impl Display for MaspFeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Error::from(self))
    }
}

impl From<&MaspFeeError> for Error {
    fn from(value: &MaspFeeError) -> Self {
        let msg = match &value.0 {
            // Destructure the error to avoid nesting a FeeError into another
            // instance of itself, which would produce a duplicated message
            Error::FeeError(inner_msg) => inner_msg,
            error => &error.to_string(),
        };

        Self::FeeError(format!(
            "The transparent balance of the fee payer was insufficient to pay \
             fees. The protocol tried to run the first transaction in the \
             batch to pay fees via the MASP but it failed: {msg}",
        ))
    }
}

impl From<MaspFeeError> for Error {
    fn from(value: MaspFeeError) -> Self {
        Self::from(&value)
    }
}

impl From<Error> for MaspFeeError {
    fn from(value: Error) -> Self {
        Self(value)
    }
}

fn try_masp_fee_payment<S, D, H, CA>(
    ShellParams {
        tx_gas_meter,
        state,
        vp_wasm_cache,
        tx_wasm_cache,
    }: &mut ShellParams<'_, S, D, H, CA>,
    tx: &Tx,
    tx_index: &TxIndex,
) -> std::result::Result<MaspTxResult, MaspFeeError>
where
    S: 'static
        + State<D = D, H = H>
        + StorageRead
        + Read<Err = state::Error>
        + ReadConversionState
        + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    // The fee payment is subject to a gas limit imposed by a protocol
    // parameter. Here we instantiate a custom gas meter for this step where the
    // gas limit is actually the lowest between the protocol parameter and the
    // actual remaining gas of the transaction. The latter is because we want to
    // enforce that no tx exceeds its own gas limit, which could happen for
    // some transactions (e.g. batches consuming a lot of gas for
    // their size) if we were to take their gas limit instead of the remaining
    // gas
    let max_gas_limit = state
        .read::<u64>(&parameters::storage::get_masp_fee_payment_gas_limit_key())
        .expect("Error reading the storage")
        .expect("Missing masp fee payment gas limit in storage")
        .min(tx_gas_meter.borrow().get_available_gas().into());
    let gas_scale = get_gas_scale(&**state).map_err(Error::Error)?;

    let masp_gas_meter = RefCell::new(TxGasMeter::new(
        Gas::from_whole_units(max_gas_limit.into(), gas_scale).ok_or_else(
            || Error::GasError("Overflow in gas expansion".to_string()),
        )?,
        gas_scale,
    ));

    let valid_batched_tx_result = {
        let first_tx = tx
            .batch_ref_first_tx()
            .ok_or_else(|| Error::MissingInnerTxs)?;
        match apply_wasm_tx(
            Some(&tx.header_hash()),
            &first_tx,
            tx_index,
            ShellParams {
                tx_gas_meter: &masp_gas_meter,
                state: *state,
                vp_wasm_cache,
                tx_wasm_cache,
            },
            GasMeterKind::MutGlobal,
        ) {
            Ok(result) => {
                // NOTE: do not commit yet cause this could be exploited to get
                // free masp operations. We can commit only after the entire fee
                // payment has been deemed valid. Also, do not commit to batch
                // cause we might need to discard the effects of this valid
                // unshield (e.g. if it unshields an amount which is not enough
                // to pay the fees)
                let is_masp_transfer = is_masp_transfer(&result.changed_keys);

                // Ensure that the transaction is actually a masp one, otherwise
                // reject
                if is_masp_transfer && result.is_accepted() {
                    let masp_section_ref = get_optional_masp_ref(
                        *state,
                        first_tx.cmt,
                        Either::Left(true),
                    )?
                    .ok_or_else(|| {
                        Error::FeeError(
                            "Missing expected masp section reference"
                                .to_string(),
                        )
                    })?;
                    MaspTxResult {
                        tx_result: result,
                        masp_section_ref,
                    }
                } else {
                    state.write_log_mut().drop_tx();

                    let error_msg = if !is_masp_transfer {
                        "Not a MASP transaction.".to_string()
                    } else {
                        format!(
                            "Some VPs rejected it: {:?}",
                            result.vps_result.errors
                        )
                    };
                    tracing::error!(error_msg);

                    return Err(Error::FeeError(error_msg).into());
                }
            }
            Err(e) => {
                state.write_log_mut().drop_tx();
                let error_msg = format!("Wasm run failed: {}", e);
                tracing::error!(error_msg);
                return Err(Error::FeeError(error_msg).into());
            }
        }
    };

    println!(
        "masp gas: {}",
        masp_gas_meter.borrow().get_consumed_gas().sub
    );
    tx_gas_meter
        .borrow_mut()
        .consume(masp_gas_meter.borrow().get_consumed_gas())
        .map_err(|e| Error::GasError(e.to_string()))?;

    Ok(valid_batched_tx_result)
}

// Check that the transaction was a MASP one and extract the MASP tx reference
// (if any) in the same order that the MASP VP follows (IBC first, Actions
// second). The order is important to prevent malicious transactions from
// messing up with indexers/clients. Also a transaction can only be of one of
// the two types, not both at the same time (the MASP VP accepts a single
// Transaction)
fn get_optional_masp_ref<S: Read<Err = state::Error>>(
    state: &S,
    cmt: &TxCommitments,
    is_masp_tx: Either<bool, &BatchedTxResult>,
) -> Result<Option<MaspTxRef>> {
    // Always check that the transaction was indeed a MASP one by looking at the
    // changed keys. A malicious tx could push a MASP Action without touching
    // any storage keys associated with the shielded pool
    let is_masp_tx = match is_masp_tx {
        Either::Left(res) => res,
        Either::Right(tx_result) => is_masp_transfer(&tx_result.changed_keys),
    };
    if !is_masp_tx {
        return Ok(None);
    }

    let masp_ref = if action::is_ibc_shielding_transfer(state)
        .map_err(Error::StateError)?
    {
        Some(MaspTxRef::IbcData(cmt.data_sechash().to_owned()))
    } else {
        let actions = state.read_actions().map_err(Error::StateError)?;
        action::get_masp_section_ref(&actions)
            .map_err(|msg| {
                Error::StateError(state::Error::new_alloc(msg.to_string()))
            })?
            .map(MaspTxRef::MaspSection)
    };

    Ok(masp_ref)
}

// Manage the token transfer for the fee payment. If an error is detected the
// write log is dropped to prevent committing an inconsistent state. Propagates
// the result to the caller
fn fee_token_transfer<WLS>(
    state: &mut WLS,
    token: &Address,
    src: &Address,
    dest: &Address,
    amount: Amount,
) -> Result<()>
where
    WLS: State + StorageRead + TxWrites,
{
    token::transfer(&mut state.with_tx_writes(), token, src, dest, amount)
        .map_err(|err| {
            state.write_log_mut().drop_tx();

            Error::Error(err)
        })
}

/// Check if the fee payer has enough transparent balance to pay fees
pub fn check_fees<S, D, H, CA>(
    shell_params: &mut ShellParams<'_, S, D, H, CA>,
    tx: &Tx,
    wrapper: &WrapperTx,
) -> Result<Option<MaspTxResult>>
where
    S: 'static
        + State<D = D, H = H>
        + StorageRead
        + Read<Err = state::Error>
        + ReadConversionState
        + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    match wrapper.get_tx_fee() {
        Ok(fees) => {
            let fees = token::denom_to_amount(
                fees,
                &wrapper.fee.token,
                shell_params.state,
            )
            .map_err(Error::Error)?;

            let balance = token::read_balance(
                shell_params.state,
                &wrapper.fee.token,
                &wrapper.fee_payer(),
            )
            .map_err(Error::Error)?;

            checked!(balance - fees).map_or_else(
                |_| {
                    // See if the first inner transaction of the batch pays
                    // the fees with a masp unshield
                    let valid_batched_tx_result = try_masp_fee_payment(
                        shell_params,
                        tx,
                        &TxIndex::default(),
                    )?;
                    let balance = token::read_balance(
                        shell_params.state,
                        &wrapper.fee.token,
                        &wrapper.fee_payer(),
                    )
                    .map_err(Error::Error)?;

                    checked!(balance - fees).map_or_else(
                        |_| {
                            Err(MaspFeeError::from(Error::FeeError(format!(
                                "Masp fee payment unshielded an insufficient \
                                 amount. Balance after unshielding: {balance} \
                                 {}, required {fees}",
                                wrapper.fee.token
                            )))
                            .into())
                        },
                        |_| Ok(Some(valid_batched_tx_result)),
                    )
                },
                |_| Ok(None),
            )
        }
        Err(e) => Err(Error::FeeError(e.to_string())),
    }
}

// Apply a transaction going via the wasm environment. Gas will be metered and
// validity predicates will be triggered in the normal way.
fn apply_wasm_tx<S, D, H, CA>(
    wrapper_hash: Option<&Hash>,
    batched_tx: &BatchedTxRef<'_>,
    tx_index: &TxIndex,
    shell_params: ShellParams<'_, S, D, H, CA>,
    gas_meter_kind: GasMeterKind,
) -> Result<BatchedTxResult>
where
    S: 'static + State<D = D, H = H> + ReadConversionState + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let ShellParams {
        tx_gas_meter,
        state,
        vp_wasm_cache,
        tx_wasm_cache,
    } = shell_params;

    let verifiers = execute_tx(
        wrapper_hash,
        batched_tx,
        tx_index,
        state,
        tx_gas_meter,
        vp_wasm_cache,
        tx_wasm_cache,
        gas_meter_kind,
    )?;
    println!(
        "apply_wasm_tx gas after tx {}",
        tx_gas_meter.borrow().transaction_gas.sub
    );

    let vps_result = check_vps(CheckVps {
        batched_tx,
        tx_index,
        state,
        tx_gas_meter: &mut tx_gas_meter.borrow_mut(),
        verifiers_from_tx: &verifiers,
        vp_wasm_cache,
        gas_meter_kind,
    })?;
    println!(
        "apply_wasm_tx gas after vps {}",
        tx_gas_meter.borrow().transaction_gas.sub
    );

    let initialized_accounts = state.write_log().get_initialized_accounts();
    let changed_keys = state.write_log().get_keys();
    let events = state.write_log_mut().take_events();

    Ok(BatchedTxResult {
        changed_keys,
        vps_result,
        initialized_accounts,
        events,
    })
}

/// Apply a derived transaction to storage based on some protocol transaction.
/// The logic here must be completely deterministic and will be executed by all
/// full nodes every time a protocol transaction is included in a block. Storage
/// is updated natively rather than via the wasm environment, so gas does not
/// need to be metered and validity predicates are bypassed. A [`TxResult`]
/// containing changed keys and the like should be returned in the normal way.
pub(crate) fn apply_protocol_tx<D, H>(
    tx: ProtocolTxType,
    data: Option<Vec<u8>>,
    state: &mut WlState<D, H>,
) -> Result<BatchedTxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    use namada_sdk::eth_bridge::protocol::transactions;
    use namada_vote_ext::{ethereum_events, validator_set_update};

    let Some(data) = data else {
        return Err(Error::ProtocolTxError(eyre!(
            "Protocol tx data must be present"
        )));
    };
    let ethereum_tx_data = EthereumTxData::deserialize(&tx, &data)
        .wrap_err_with(|| {
            format!(
                "Attempt made to apply an unsupported protocol transaction! - \
                 {tx:?}",
            )
        })
        .map_err(Error::ProtocolTxError)?;

    match ethereum_tx_data {
        EthereumTxData::EthEventsVext(
            namada_vote_ext::ethereum_events::SignedVext(ext),
        ) => {
            let ethereum_events::VextDigest { events, .. } =
                ethereum_events::VextDigest::singleton(ext);
            transactions::ethereum_events::apply_derived_tx::<
                _,
                _,
                governance::Store<_>,
            >(state, events)
            .map_err(Error::ProtocolTxError)
        }
        EthereumTxData::BridgePoolVext(ext) => {
            transactions::bridge_pool_roots::apply_derived_tx::<
                _,
                _,
                governance::Store<_>,
            >(state, ext.into())
            .map_err(Error::ProtocolTxError)
        }
        EthereumTxData::ValSetUpdateVext(ext) => {
            // NOTE(feature = "abcipp"): with ABCI++, we can write the
            // complete proof to storage in one go. the decided vote extension
            // digest must already have >2/3 of the voting power behind it.
            // with ABCI+, multiple vote extension protocol txs may be needed
            // to reach a complete proof.
            let signing_epoch = ext.data.signing_epoch;
            transactions::validator_set_update::aggregate_votes::<
                _,
                _,
                governance::Store<_>,
            >(
                state,
                validator_set_update::VextDigest::singleton(ext),
                signing_epoch,
            )
            .map_err(Error::ProtocolTxError)
        }
        EthereumTxData::EthereumEvents(_)
        | EthereumTxData::BridgePool(_)
        | EthereumTxData::ValidatorSetUpdate(_) => {
            // TODO(namada#198): implement this
            tracing::warn!(
                "Attempt made to apply an unimplemented protocol transaction, \
                 no actions will be taken"
            );
            Ok(BatchedTxResult::default())
        }
    }
}

/// Execute a transaction code. Returns verifiers requested by the transaction.
#[allow(clippy::too_many_arguments)]
fn execute_tx<S, D, H, CA>(
    wrapper_hash: Option<&Hash>,
    batched_tx: &BatchedTxRef<'_>,
    tx_index: &TxIndex,
    state: &mut S,
    tx_gas_meter: &RefCell<TxGasMeter>,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
    gas_meter_kind: GasMeterKind,
) -> Result<BTreeSet<Address>>
where
    S: State<D = D, H = H>,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    wasm::run::tx(
        state,
        tx_gas_meter,
        wrapper_hash,
        tx_index,
        batched_tx.tx,
        batched_tx.cmt,
        vp_wasm_cache,
        tx_wasm_cache,
        gas_meter_kind,
    )
    .map_err(|err| match err {
        wasm::run::Error::GasError(msg) => Error::GasError(msg),
        wasm::run::Error::MissingSection(msg) => Error::MissingSection(msg),
        _ => Error::TxRunnerError(err),
    })
}

/// Arguments to [`check_vps`].
struct CheckVps<'a, S, CA>
where
    S: State,
    CA: 'static + WasmCacheAccess + Sync,
{
    batched_tx: &'a BatchedTxRef<'a>,
    tx_index: &'a TxIndex,
    state: &'a S,
    tx_gas_meter: &'a mut TxGasMeter,
    verifiers_from_tx: &'a BTreeSet<Address>,
    vp_wasm_cache: &'a mut VpCache<CA>,
    gas_meter_kind: GasMeterKind,
}

/// Check the acceptance of a transaction by validity predicates
fn check_vps<S, CA>(
    CheckVps {
        batched_tx: tx,
        tx_index,
        state,
        tx_gas_meter,
        verifiers_from_tx,
        vp_wasm_cache,
        gas_meter_kind,
    }: CheckVps<'_, S, CA>,
) -> Result<VpsResult>
where
    S: 'static + ReadConversionState + State + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let (verifiers, keys_changed) = state
        .write_log()
        .verifiers_and_changed_keys(verifiers_from_tx);

    let (vps_result, vps_gas) = execute_vps(
        verifiers,
        keys_changed,
        tx,
        tx_index,
        state,
        tx_gas_meter,
        vp_wasm_cache,
        gas_meter_kind,
    )?;
    tracing::debug!("Total VPs gas cost {:?}", vps_gas);

    tx_gas_meter
        .consume(vps_gas)
        .map_err(|err| Error::GasError(err.to_string()))?;

    Ok(vps_result)
}

/// Execute verifiers' validity predicates
#[allow(clippy::too_many_arguments)]
fn execute_vps<S, CA>(
    verifiers: BTreeSet<Address>,
    keys_changed: BTreeSet<storage::Key>,
    batched_tx: &BatchedTxRef<'_>,
    tx_index: &TxIndex,
    state: &S,
    tx_gas_meter: &TxGasMeter,
    vp_wasm_cache: &mut VpCache<CA>,
    gas_meter_kind: GasMeterKind,
) -> Result<(VpsResult, namada_sdk::gas::Gas)>
where
    S: 'static + ReadConversionState + State + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let vps_result = verifiers
        .par_iter()
        .try_fold(
            || (VpsResult::default(), Gas::from(0)),
            |(mut result, mut vps_gas), addr| {
                let gas_meter =
                    RefCell::new(VpGasMeter::new_from_meter(tx_gas_meter));
                let tx_accepted = match &addr {
                    Address::Implicit(_) | Address::Established(_) => {
                        let (vp_hash, gas) = state
                            .validity_predicate::<parameters::Store<()>>(addr)
                            .map_err(Error::StateError)?;
                        gas_meter
                            .borrow_mut()
                            .consume(gas)
                            .map_err(|err| Error::GasError(err.to_string()))?;
                        let Some(vp_code_hash) = vp_hash else {
                            return Err(Error::MissingAddress(addr.clone()));
                        };

                        wasm::run::vp(
                            vp_code_hash,
                            batched_tx,
                            tx_index,
                            addr,
                            state,
                            &gas_meter,
                            &keys_changed,
                            &verifiers,
                            vp_wasm_cache.clone(),
                            gas_meter_kind,
                        )
                        .map_err(|err| match err {
                            wasm::run::Error::GasError(msg) => {
                                Error::GasError(msg)
                            }
                            wasm::run::Error::InvalidSectionSignature(msg) => {
                                Error::InvalidSectionSignature(msg)
                            }
                            _ => Error::VpRunnerError(err),
                        })
                    }
                    Address::Internal(internal_addr) => {
                        let ctx = NativeVpCtx::new(
                            addr,
                            state,
                            batched_tx.tx,
                            batched_tx.cmt,
                            tx_index,
                            &gas_meter,
                            &keys_changed,
                            &verifiers,
                            vp_wasm_cache.clone(),
                            GasMeterKind::MutGlobal,
                        );

                        match internal_addr {
                            InternalAddress::PoS => PosVp::validate_tx(
                                &ctx,
                                batched_tx,
                                &keys_changed,
                                &verifiers,
                            )
                            .map_err(Error::NativeVpError),
                            InternalAddress::Ibc => {
                                let ibc = IbcVp::new(ctx);
                                ibc.validate_tx(
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::NativeVpError)
                            }
                            InternalAddress::Parameters => {
                                ParametersVp::validate_tx(
                                    &ctx,
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::NativeVpError)
                            }
                            InternalAddress::PosSlashPool => {
                                Err(Error::AccessForbidden(
                                    (*internal_addr).clone(),
                                ))
                            }
                            InternalAddress::Governance => {
                                GovernanceVp::validate_tx(
                                    &ctx,
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::NativeVpError)
                            }
                            InternalAddress::Pgf => PgfVp::validate_tx(
                                &ctx,
                                batched_tx,
                                &keys_changed,
                                &verifiers,
                            )
                            .map_err(Error::NativeVpError),
                            InternalAddress::Multitoken => {
                                MultitokenVp::validate_tx(
                                    &ctx,
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::NativeVpError)
                            }
                            InternalAddress::Masp => MaspVp::validate_tx(
                                &ctx,
                                batched_tx,
                                &keys_changed,
                                &verifiers,
                            )
                            .map_err(Error::NativeVpError),
                            InternalAddress::EthBridge => {
                                EthBridgeVp::validate_tx(
                                    &ctx,
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::NativeVpError)
                            }
                            InternalAddress::EthBridgePool => {
                                EthBridgePoolVp::validate_tx(
                                    &ctx,
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::NativeVpError)
                            }
                            InternalAddress::Nut(_) => {
                                EthBridgeNutVp::validate_tx(
                                    &ctx,
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::NativeVpError)
                            }
                            internal_addr @ (InternalAddress::IbcToken(_)
                            | InternalAddress::Erc20(_)) => {
                                // The address should be a part of a multitoken
                                // key
                                verifiers
                                    .contains(&Address::Internal(
                                        InternalAddress::Multitoken,
                                    ))
                                    .ok_or_else(|| {
                                        Error::AccessForbidden(
                                            internal_addr.clone(),
                                        )
                                    })
                            }
                            InternalAddress::TempStorage => Err(
                                // Temp storage changes must never be committed
                                Error::AccessForbidden(
                                    (*internal_addr).clone(),
                                ),
                            ),
                            InternalAddress::ReplayProtection => Err(
                                // Replay protection entries should never be
                                // written to via transactions
                                Error::AccessForbidden(
                                    (*internal_addr).clone(),
                                ),
                            ),
                        }
                    }
                };

                tx_accepted.map_or_else(
                    |err| {
                        result
                            .status_flags
                            .insert(err.invalid_section_signature_flag());
                        result.rejected_vps.insert(addr.clone());
                        result.errors.push((addr.clone(), err.to_string()));
                    },
                    |()| {
                        result.accepted_vps.insert(addr.clone());
                    },
                );

                // Execution of VPs can (and must) be short-circuited
                // only in case of a gas overflow to prevent the
                // transaction from consuming resources that have not
                // been acquired in the corresponding wrapper tx. For
                // all the other errors we keep evaluating the vps. This
                // allows to display a consistent VpsResult across all
                // nodes and find any invalid signatures
                vps_gas = vps_gas
                    .checked_add(gas_meter.borrow().get_vp_consumed_gas())
                    .ok_or(Error::GasError(
                        gas::Error::GasOverflow.to_string(),
                    ))?;
                gas_meter
                    .borrow()
                    .check_limit(vps_gas.clone())
                    .map_err(|err| Error::GasError(err.to_string()))?;

                Ok((result, vps_gas))
            },
        )
        .try_reduce(
            || (VpsResult::default(), Gas::from(0)),
            |a, b| merge_vp_results(a, b, tx_gas_meter),
        )?;

    Ok(vps_result)
}

/// Merge VP results from parallel runs
fn merge_vp_results(
    (a, a_gas): (VpsResult, Gas),
    (mut b, b_gas): (VpsResult, Gas),
    tx_gas_meter: &TxGasMeter,
) -> Result<(VpsResult, Gas)> {
    let mut accepted_vps = a.accepted_vps;
    let mut rejected_vps = a.rejected_vps;
    accepted_vps.extend(b.accepted_vps);
    rejected_vps.extend(b.rejected_vps);
    let mut errors = a.errors;
    errors.append(&mut b.errors);
    let status_flags = a.status_flags | b.status_flags;

    let vps_gas = a_gas
        .checked_add(b_gas)
        .ok_or(Error::GasError(gas::Error::GasOverflow.to_string()))?;
    tx_gas_meter
        .check_limit(vps_gas.clone())
        .map_err(|err| Error::GasError(err.to_string()))?;

    Ok((
        VpsResult {
            accepted_vps,
            rejected_vps,
            errors,
            status_flags,
        },
        vps_gas,
    ))
}

#[cfg(test)]
mod tests {
    use eyre::Result;
    use namada_sdk::account::pks_handle;
    use namada_sdk::chain::BlockHeight;
    use namada_sdk::collections::HashMap;
    use namada_sdk::eth_bridge::protocol::transactions::votes::{
        EpochedVotingPower, Votes,
    };
    use namada_sdk::eth_bridge::storage::eth_bridge_queries::EthBridgeQueries;
    use namada_sdk::eth_bridge::storage::proof::EthereumProof;
    use namada_sdk::eth_bridge::storage::{vote_tallies, vp};
    use namada_sdk::eth_bridge::test_utils;
    use namada_sdk::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
    use namada_sdk::ethereum_events::{EthereumEvent, TransferToNamada};
    use namada_sdk::keccak::keccak_hash;
    use namada_sdk::key::RefTo;
    use namada_sdk::testing::{
        arb_tampered_inner_tx, arb_valid_signed_inner_tx,
    };
    use namada_sdk::tx::{SignableEthMessage, Signed};
    use namada_sdk::voting_power::FractionalVotingPower;
    use namada_sdk::{address, key};
    use namada_test_utils::TestWasms;
    use namada_vote_ext::bridge_pool_roots::BridgePoolRootVext;
    use namada_vote_ext::ethereum_events::EthereumEventsVext;
    use namada_vp::state::StorageWrite;
    use proptest::test_runner::{Config, TestRunner};

    use super::*;

    fn apply_eth_tx<D, H>(
        tx: EthereumTxData,
        state: &mut WlState<D, H>,
    ) -> Result<BatchedTxResult>
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
    {
        let (data, tx) = tx.serialize();
        let tx_result = apply_protocol_tx(tx, Some(data), state)?;
        Ok(tx_result)
    }

    #[test]
    /// Tests that if the same [`ProtocolTxType::EthEventsVext`] is applied
    /// twice within the same block, it doesn't result in voting power being
    /// double counted.
    fn test_apply_protocol_tx_duplicate_eth_events_vext() -> Result<()> {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let validator_a_stake = Amount::native_whole(100);
        let validator_b_stake = Amount::native_whole(100);
        let total_stake = validator_a_stake + validator_b_stake;
        let (mut state, _) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), validator_a_stake),
                (validator_b, validator_b_stake),
            ]),
        );
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver: address::testing::established_address_4(),
            }],
        };
        let vext = EthereumEventsVext {
            block_height: BlockHeight(100),
            validator_addr: address::testing::established_address_2(),
            ethereum_events: vec![event.clone()],
        };
        let signing_key = key::testing::keypair_1();
        let signed = vext.sign(&signing_key);
        let tx = EthereumTxData::EthEventsVext(
            namada_vote_ext::ethereum_events::SignedVext(signed),
        );

        apply_eth_tx(tx.clone(), &mut state)?;
        apply_eth_tx(tx, &mut state)?;

        let eth_msg_keys = vote_tallies::Keys::from(&event);
        let seen_by: Votes = state.read(&eth_msg_keys.seen_by())?.unwrap();
        assert_eq!(seen_by, Votes::from([(validator_a, BlockHeight(100))]));

        // the vote should have only be applied once
        let voting_power: EpochedVotingPower =
            state.read(&eth_msg_keys.voting_power())?.unwrap();
        let expected = EpochedVotingPower::from([(
            0.into(),
            FractionalVotingPower::HALF * total_stake,
        )]);
        assert_eq!(voting_power, expected);

        Ok(())
    }

    #[test]
    /// Tests that if the same [`ProtocolTxType::BridgePoolVext`] is applied
    /// twice within the same block, it doesn't result in voting power being
    /// double counted.
    fn test_apply_protocol_tx_duplicate_bp_roots_vext() -> Result<()> {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let validator_a_stake = Amount::native_whole(100);
        let validator_b_stake = Amount::native_whole(100);
        let total_stake = validator_a_stake + validator_b_stake;
        let (mut state, keys) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), validator_a_stake),
                (validator_b, validator_b_stake),
            ]),
        );
        vp::bridge_pool::init_storage(&mut state);

        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        test_utils::commit_bridge_pool_root_at_height(
            &mut state,
            &root,
            100.into(),
        );
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let signing_key = key::testing::keypair_1();
        let hot_key =
            &keys[&address::testing::established_address_2()].eth_bridge;
        let sig = Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig;
        let vext = BridgePoolRootVext {
            block_height: BlockHeight(100),
            validator_addr: address::testing::established_address_2(),
            sig,
        }
        .sign(&signing_key);
        let tx = EthereumTxData::BridgePoolVext(vext);
        apply_eth_tx(tx.clone(), &mut state)?;
        apply_eth_tx(tx, &mut state)?;

        let bp_root_keys = vote_tallies::Keys::from((
            &vote_tallies::BridgePoolRoot(EthereumProof::new((root, nonce))),
            100.into(),
        ));
        let root_seen_by: Votes = state.read(&bp_root_keys.seen_by())?.unwrap();
        assert_eq!(
            root_seen_by,
            Votes::from([(validator_a, BlockHeight(100))])
        );
        // the vote should have only be applied once
        let voting_power: EpochedVotingPower =
            state.read(&bp_root_keys.voting_power())?.unwrap();
        let expected = EpochedVotingPower::from([(
            0.into(),
            FractionalVotingPower::HALF * total_stake,
        )]);
        assert_eq!(voting_power, expected);

        Ok(())
    }

    #[test]
    fn test_native_vp_out_of_gas() {
        let (mut state, _validators) = test_utils::setup_default_storage();

        // some random token address
        let token_address = Address::Established([0xff; 20].into());

        let src_address = Address::Established([0xab; 20].into());
        let dst_address = Address::Established([0xba; 20].into());

        // supply an address with 1000 of said token
        token::credit_tokens(
            &mut state,
            &token_address,
            &src_address,
            1000.into(),
        )
        .unwrap();

        // commit storage changes. this will act as the
        // initial state of the chain
        state.commit_tx_batch();
        state.commit_block().unwrap();

        // "execute" a dummy tx, by manually performing its state changes
        let (dummy_tx, changed_keys, verifiers) = {
            let mut tx = Tx::from_type(namada_sdk::tx::data::TxType::Raw);
            tx.set_code(namada_sdk::tx::Code::new(vec![], None));
            tx.set_data(namada_sdk::tx::Data::new(vec![]));

            // transfer half of the supply of src to dst
            token::transfer(
                &mut state,
                &token_address,
                &src_address,
                &dst_address,
                500.into(),
            )
            .unwrap();

            let changed_keys = {
                let mut set = BTreeSet::new();
                set.insert(token::storage_key::balance_key(
                    &token_address,
                    &src_address,
                ));
                set.insert(token::storage_key::balance_key(
                    &token_address,
                    &dst_address,
                ));
                set
            };

            let verifiers = {
                let mut set = BTreeSet::new();
                set.insert(Address::Internal(InternalAddress::Multitoken));
                set
            };

            (tx, changed_keys, verifiers)
        };

        // temp vp cache
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::cache();

        // gas meter with no gas left
        let gas_meter = TxGasMeter::new(0, get_gas_scale(&state).unwrap());

        let batched_tx = dummy_tx.batch_ref_first_tx().unwrap();
        let result = execute_vps(
            verifiers,
            changed_keys,
            &batched_tx,
            &TxIndex::default(),
            &state,
            &gas_meter,
            &mut vp_cache,
            GasMeterKind::MutGlobal,
        );
        assert!(matches!(result.unwrap_err(), Error::GasError(_)));
    }

    // Test that the host function for signature verification we expose allows
    // the vps to detect a tx that has been tampered with
    #[test]
    fn test_tampered_inner_tx_rejected() {
        let (mut state, _validators) = test_utils::setup_default_storage();
        let signing_key = key::testing::keypair_1();
        let pk = signing_key.ref_to();
        let addr = Address::from(&pk);

        // Reveal the pk
        pks_handle(&addr)
            .insert(&mut state, 0_u8, pk.clone())
            .unwrap();

        // Allowlist the vp for the signature verification
        let vp_code = TestWasms::VpVerifySignature.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_code);
        let key = namada_sdk::storage::Key::wasm_code(&code_hash);
        let len_key = namada_sdk::storage::Key::wasm_code_len(&code_hash);
        let code_len = vp_code.len() as u64;
        state.write(&key, vp_code).unwrap();
        state.write(&len_key, code_len).unwrap();

        let (vp_cache, _) = wasm::compilation_cache::common::testing::cache();

        let mut runner = TestRunner::new(Config::default());
        // Test that the strategy produces valid txs first
        let result =
            runner.run(&arb_valid_signed_inner_tx(signing_key.clone()), |tx| {
                for cmt in tx.commitments() {
                    let batched_tx = BatchedTxRef { tx: &tx, cmt };
                    assert!(
                        wasm::run::vp(
                            code_hash,
                            &batched_tx,
                            &TxIndex::default(),
                            &addr,
                            &state,
                            &RefCell::new(VpGasMeter::new_from_tx_meter(
                                &TxGasMeter::new(
                                    u64::MAX,
                                    get_gas_scale(&state).unwrap()
                                ),
                            )),
                            &Default::default(),
                            &Default::default(),
                            vp_cache.clone(),
                            GasMeterKind::MutGlobal,
                        )
                        .is_ok()
                    );
                }
                Ok(())
            });
        assert!(result.is_ok());

        // Then test tampered txs
        let mut runner = TestRunner::new(Config::default());
        let result = runner.run(&arb_tampered_inner_tx(signing_key), |tx| {
            for cmt in tx.commitments() {
                let batched_tx = BatchedTxRef { tx: &tx, cmt };
                assert!(
                    wasm::run::vp(
                        code_hash,
                        &batched_tx,
                        &TxIndex::default(),
                        &addr,
                        &state,
                        &RefCell::new(VpGasMeter::new_from_tx_meter(
                            &TxGasMeter::new(
                                u64::MAX,
                                get_gas_scale(&state).unwrap()
                            )
                        )),
                        &Default::default(),
                        &Default::default(),
                        vp_cache.clone(),
                        GasMeterKind::MutGlobal,
                    )
                    .is_err()
                );
            }
            Ok(())
        });
        assert!(result.is_ok());
    }
}
