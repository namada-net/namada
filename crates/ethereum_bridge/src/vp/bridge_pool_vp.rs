//! Validity predicate for the Ethereum bridge pool
//!
//! This pool holds user initiated transfers of value from
//! Namada to Ethereum. It is to act like a mempool: users
//! add in their desired transfers and their chosen amount
//! of NAM to cover Ethereum side gas fees. These transfers
//! can be relayed in batches along with Merkle proofs.
//!
//! This VP checks that additions to the pool are handled
//! correctly. This means that the appropriate data is
//! added to the pool and gas fees are submitted appropriately
//! and that tokens to be transferred are escrowed.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::marker::PhantomData;

use borsh::BorshDeserialize;
use namada_core::address::{Address, InternalAddress};
use namada_core::arith::{CheckedAdd, CheckedNeg, CheckedSub, checked};
use namada_core::booleans::BoolResultUnitExt;
use namada_core::eth_bridge_pool::{
    PendingTransfer, TransferToEthereumKind, erc20_token_address,
};
use namada_core::ethereum_events::EthAddress;
use namada_core::hints;
use namada_core::storage::Key;
use namada_core::uint::I320;
use namada_state::ResultExt;
use namada_systems::trans_token::{self as token, Amount};
use namada_tx::BatchedTxRef;
use namada_vp_env::{Error, Result, StorageRead, VpEnv};

use crate::ADDRESS as BRIDGE_ADDRESS;
use crate::storage::bridge_pool::{
    BRIDGE_POOL_ADDRESS, get_pending_key, is_bridge_pool_key,
};
use crate::storage::eth_bridge_queries::is_bridge_active_at;
use crate::storage::parameters::read_native_erc20_address;
use crate::storage::whitelist;

/// An [`Amount`] that has been updated with some delta value.
#[derive(Copy, Clone)]
struct AmountDelta {
    /// The base [`Amount`], before applying the delta.
    base: Amount,
    /// The delta to be applied to the base amount.
    delta: I320,
}

impl AmountDelta {
    /// Resolve the updated amount by applying the delta value.
    #[inline]
    fn resolve(self) -> Result<I320> {
        checked!(self.delta + I320::from(self.base)).map_err(Into::into)
    }
}

/// Validity predicate for the Ethereum bridge
pub struct BridgePool<'ctx, CTX, TokenKeys> {
    /// Generic types for DI
    pub _marker: PhantomData<(&'ctx CTX, TokenKeys)>,
}

impl<'ctx, CTX, TokenKeys> BridgePool<'ctx, CTX, TokenKeys>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
    TokenKeys: token::Keys,
{
    /// Run the validity predicate
    pub fn validate_tx(
        ctx: &'ctx CTX,
        batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        tracing::debug!(
            keys_changed_len = keys_changed.len(),
            verifiers_len = _verifiers.len(),
            "Ethereum Bridge Pool VP triggered",
        );
        if !is_bridge_active_at(&ctx.pre(), ctx.get_block_epoch()?)? {
            tracing::debug!(
                "Rejecting transaction, since the Ethereum bridge is disabled."
            );
            return Err(Error::new_const(
                "Rejecting transaction, since the Ethereum bridge is disabled.",
            ));
        }
        let Some(tx_data) = batched_tx.tx.data(batched_tx.cmt) else {
            return Err(Error::new_const("No transaction data found"));
        };
        let transfer: PendingTransfer =
            BorshDeserialize::try_from_slice(&tx_data[..])
                .into_storage_result()?;

        let pending_key = get_pending_key(&transfer);
        // check that transfer is not already in the pool
        match ctx.pre().read::<PendingTransfer>(&pending_key) {
            Ok(Some(_)) => {
                let error = Error::new_const(
                    "Rejecting transaction as the transfer is already in the \
                     Ethereum bridge pool.",
                );
                tracing::debug!("{error}");
                return Err(error);
            }
            // NOTE: make sure we don't erase storage errors returned by the
            // ctx, as these may contain gas errors!
            Err(e) => return Err(e),
            _ => {}
        }
        for key in keys_changed.iter().filter(|k| is_bridge_pool_key(k)) {
            if *key != pending_key {
                let error = Error::new_alloc(format!(
                    "Rejecting transaction as it is attempting to change an \
                     incorrect key in the Ethereum bridge pool: {key}.\n \
                     Expected key: {pending_key}",
                ));
                tracing::debug!("{error}");
                return Err(error);
            }
        }
        let pending: PendingTransfer =
            ctx.post().read(&pending_key)?.ok_or_else(|| {
                Error::new_const(
                    "Rejecting transaction as the transfer wasn't added to \
                     the pool of pending transfers",
                )
            })?;
        if pending != transfer {
            let error = Error::new_alloc(format!(
                "An incorrect transfer was added to the Ethereum bridge pool: \
                 {transfer:?}.\n Expected: {pending:?}",
            ));
            tracing::debug!("{error}");
            return Err(error);
        }
        // The deltas in the escrowed amounts we must check.
        let wnam_address = read_native_erc20_address(&ctx.pre())?;
        let escrow_checks =
            Self::determine_escrow_checks(ctx, &wnam_address, &transfer)?;
        if !escrow_checks.validate::<TokenKeys>(keys_changed) {
            let error = Error::new_const(
                // TODO(namada#3247): specify which storage changes are missing
                // or which ones are invalid
                "Invalid storage modifications in the Bridge pool",
            );
            tracing::debug!("{error}");
            return Err(error);
        }
        // check that gas was correctly escrowed.
        if !Self::check_gas_escrow(
            ctx,
            &wnam_address,
            &transfer,
            escrow_checks.gas_check,
        )? {
            return Err(Error::new_const(
                "Gas was not correctly escrowed into the Bridge pool storage",
            ));
        }
        // check the escrowed assets
        if transfer.transfer.asset == wnam_address {
            Self::check_wnam_escrow(
                ctx,
                &wnam_address,
                &transfer,
                escrow_checks.token_check,
            )?
            .ok_or_else(|| {
                Error::new_const(
                    "The wrapped NAM tokens were not escrowed properly",
                )
            })
        } else {
            Self::check_escrowed_toks(ctx, escrow_checks.token_check)?
                .ok_or_else(|| {
                    Error::new_alloc(format!(
                        "The {} tokens were not escrowed properly",
                        transfer.transfer.asset
                    ))
                })
        }
        .inspect(|_| {
            tracing::info!(
                "The Ethereum bridge pool VP accepted the transfer {:?}.",
                transfer
            );
        })
        .inspect_err(|err| {
            tracing::debug!(
                ?transfer,
                reason = ?err,
                "The assets of the transfer were not properly escrowed \
                 into the Ethereum bridge pool."
            );
        })
    }

    /// Get the change in the balance of an account
    /// associated with an address
    fn account_balance_delta(
        ctx: &'ctx CTX,
        token: &Address,
        address: &Address,
    ) -> Result<Option<AmountDelta>> {
        let account_key = TokenKeys::balance_key(token, address);
        let before: Amount = ctx
            .pre()
            .read(&account_key)
            .map_err(|error| {
                tracing::warn!(?error, %account_key, "reading pre value");
                error
            })?
            // NB: the previous balance of the given account might
            // have been null. this is valid if the account is
            // being credited, such as when we escrow gas under
            // the Bridge pool
            .unwrap_or_default();
        let after: Amount = match ctx.post().read(&account_key)? {
            Some(after) => after,
            None => {
                tracing::warn!(%account_key, "no post value");
                return Ok(None);
            }
        };
        Ok(Some(AmountDelta {
            base: before,
            delta: checked!(I320::from(after) - I320::from(before)).map_err(
                |error| {
                    tracing::warn!(?error, %account_key, "reading pre value");
                    error
                },
            )?,
        }))
    }

    /// Check that the correct amount of tokens were sent
    /// from the correct account into escrow.
    #[inline]
    fn check_escrowed_toks<K>(
        ctx: &'ctx CTX,
        delta: EscrowDelta<'_, K>,
    ) -> Result<bool> {
        Self::check_escrowed_toks_balance(ctx, delta)
            .map(|balance| balance.is_some())
    }

    /// Check that the correct amount of tokens were sent
    /// from the correct account into escrow, and return
    /// the updated escrow balance.
    fn check_escrowed_toks_balance<K>(
        ctx: &'ctx CTX,
        delta: EscrowDelta<'_, K>,
    ) -> Result<Option<AmountDelta>> {
        let EscrowDelta {
            token,
            payer_account,
            escrow_account,
            expected_debit,
            expected_credit,
            ..
        } = delta;
        let debit = Self::account_balance_delta(ctx, &token, payer_account)?;
        let credit = Self::account_balance_delta(ctx, &token, escrow_account)?;

        match (debit, credit) {
            // success case
            (
                Some(AmountDelta { delta: debit, .. }),
                Some(escrow_balance @ AmountDelta { delta: credit, .. }),
            ) if !debit.is_positive() && !credit.is_negative() => {
                Ok((Some(debit) == I320::from(expected_debit).checked_neg()
                    && credit == I320::from(expected_credit))
                .then_some(escrow_balance))
            }
            // user did not debit from their account
            (Some(AmountDelta { delta, .. }), _) if !delta.is_negative() => {
                tracing::debug!(
                    "The account {} was not debited.",
                    payer_account
                );
                Ok(None)
            }
            // user did not credit escrow account
            (_, Some(AmountDelta { delta, .. })) if !delta.is_positive() => {
                tracing::debug!(
                    "The Ethereum bridge pool's escrow was not credited from \
                     account {}.",
                    payer_account
                );
                Ok(None)
            }
            // some other error occurred while calculating
            // balance deltas
            _ => Err(Error::AllocMessage(format!(
                "Could not calculate the balance delta for {}",
                payer_account
            ))),
        }
    }

    /// Check that the gas was correctly escrowed.
    fn check_gas_escrow(
        ctx: &'ctx CTX,
        wnam_address: &EthAddress,
        transfer: &PendingTransfer,
        gas_check: EscrowDelta<'_, GasCheck>,
    ) -> Result<bool> {
        if hints::unlikely(
            *gas_check.token == erc20_token_address(wnam_address),
        ) {
            // NB: this should never be possible: protocol tx state updates
            // never result in wNAM ERC20s being minted
            tracing::error!(
                ?transfer,
                "Attempted to pay Bridge pool fees with wrapped NAM."
            );
            return Ok(false);
        }
        if matches!(
            &*gas_check.token,
            Address::Internal(InternalAddress::Nut(_))
        ) {
            tracing::debug!(
                ?transfer,
                "The gas fees of the transfer cannot be paid in NUTs."
            );
            return Ok(false);
        }
        if !Self::check_escrowed_toks(ctx, gas_check)? {
            tracing::debug!(
                ?transfer,
                "The gas fees of the transfer were not properly escrowed into \
                 the Ethereum bridge pool."
            );
            return Ok(false);
        }
        Ok(true)
    }

    /// Validate a wrapped NAM transfer to Ethereum.
    fn check_wnam_escrow(
        ctx: &'ctx CTX,
        &wnam_address: &EthAddress,
        transfer: &PendingTransfer,
        token_check: EscrowDelta<'_, TokenCheck>,
    ) -> Result<bool> {
        if hints::unlikely(matches!(
            &transfer.transfer.kind,
            TransferToEthereumKind::Nut
        )) {
            // NB: this should never be possible: protocol tx state updates
            // never result in wNAM NUTs being minted. in turn, this means
            // that users should never hold wNAM NUTs. doesn't hurt to add
            // the extra check to the vp, though
            tracing::error!(
                ?transfer,
                "Attempted to add a wNAM NUT transfer to the Bridge pool"
            );
            return Ok(false);
        }

        let wnam_whitelisted = {
            let key = whitelist::Key {
                asset: wnam_address,
                suffix: whitelist::KeyType::Whitelisted,
            }
            .into();
            ctx.pre().read(&key)?.unwrap_or(false)
        };
        if !wnam_whitelisted {
            tracing::debug!(
                ?transfer,
                "Wrapped NAM transfers are currently disabled"
            );
            return Ok(false);
        }

        // if we are going to mint wNam on Ethereum, the appropriate
        // amount of Nam must be escrowed in the Ethereum bridge VP's
        // storage.
        let escrowed_balance =
            match Self::check_escrowed_toks_balance(ctx, token_check)? {
                Some(balance) => balance.resolve()?,
                None => return Ok(false),
            };

        let wnam_cap: Amount = {
            let key = whitelist::Key {
                asset: wnam_address,
                suffix: whitelist::KeyType::Cap,
            }
            .into();
            ctx.pre().read(&key)?.unwrap_or_default()
        };
        if escrowed_balance > I320::from(wnam_cap) {
            tracing::debug!(
                ?transfer,
                escrowed_nam = %escrowed_balance.to_string_native(),
                wnam_cap = %wnam_cap.to_string_native(),
                "The balance of the escrow account exceeds the amount \
                 of NAM that is allowed to cross the Ethereum bridge"
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Determine the debit and credit amounts that should be checked.
    fn determine_escrow_checks<'trans>(
        ctx: &'ctx CTX,
        wnam_address: &EthAddress,
        transfer: &'trans PendingTransfer,
    ) -> Result<EscrowCheck<'trans>> {
        let tok_is_native_asset = &transfer.transfer.asset == wnam_address;

        // NB: this comparison is not enough to check
        // if NAM is being used for both tokens and gas
        // fees, since wrapped NAM will have a different
        // token address
        let same_token_and_gas_erc20 =
            transfer.token_address() == transfer.gas_fee.token;

        let (expected_gas_debit, expected_token_debit) = {
            // NB: there is a corner case where the gas fees and escrowed
            // tokens are debited from the same address, when the gas fee
            // payer and token sender are the same, and the underlying
            // transferred assets are the same
            let same_sender_and_fee_payer =
                transfer.gas_fee.payer == transfer.transfer.sender;
            let gas_is_native_asset =
                transfer.gas_fee.token == ctx.get_native_token()?;
            let gas_and_token_is_native_asset =
                gas_is_native_asset && tok_is_native_asset;
            let same_token_and_gas_asset =
                gas_and_token_is_native_asset || same_token_and_gas_erc20;
            let same_debited_address =
                same_sender_and_fee_payer && same_token_and_gas_asset;

            if same_debited_address {
                let debit = sum_gas_and_token_amounts(transfer)?;
                (debit, debit)
            } else {
                (transfer.gas_fee.amount, transfer.transfer.amount)
            }
        };
        let (expected_gas_credit, expected_token_credit) = {
            // NB: there is a corner case where the gas fees and escrowed
            // tokens are credited to the same address, when the underlying
            // transferred assets are the same (unless the asset is NAM)
            let same_credited_address = same_token_and_gas_erc20;

            if same_credited_address {
                let credit = sum_gas_and_token_amounts(transfer)?;
                (credit, credit)
            } else {
                (transfer.gas_fee.amount, transfer.transfer.amount)
            }
        };
        let (token_check_addr, token_check_escrow_acc) = if tok_is_native_asset
        {
            // when minting wrapped NAM on Ethereum, escrow to the Ethereum
            // bridge address, and draw from NAM token accounts
            let token = Cow::Owned(ctx.get_native_token()?);
            let escrow_account = &BRIDGE_ADDRESS;
            (token, escrow_account)
        } else {
            // otherwise, draw from ERC20/NUT wrapped asset token accounts,
            // and escrow to the Bridge pool address
            let token = Cow::Owned(transfer.token_address());
            let escrow_account = &BRIDGE_POOL_ADDRESS;
            (token, escrow_account)
        };

        Ok(EscrowCheck {
            gas_check: EscrowDelta {
                // NB: it's fine to not check for wrapped NAM here,
                // as users won't hold wrapped NAM tokens in practice,
                // anyway
                token: Cow::Borrowed(&transfer.gas_fee.token),
                payer_account: &transfer.gas_fee.payer,
                escrow_account: &BRIDGE_POOL_ADDRESS,
                expected_debit: expected_gas_debit,
                expected_credit: expected_gas_credit,
                transferred_amount: &transfer.gas_fee.amount,
                _kind: PhantomData,
            },
            token_check: EscrowDelta {
                token: token_check_addr,
                payer_account: &transfer.transfer.sender,
                escrow_account: token_check_escrow_acc,
                expected_debit: expected_token_debit,
                expected_credit: expected_token_credit,
                transferred_amount: &transfer.transfer.amount,
                _kind: PhantomData,
            },
        })
    }
}

/// Helper struct for handling the different escrow
/// checking scenarios.
struct EscrowDelta<'ctx, KIND> {
    token: Cow<'ctx, Address>,
    payer_account: &'ctx Address,
    escrow_account: &'ctx Address,
    expected_debit: Amount,
    expected_credit: Amount,
    transferred_amount: &'ctx Amount,
    _kind: PhantomData<*const KIND>,
}

impl<KIND> EscrowDelta<'_, KIND> {
    /// Validate an [`EscrowDelta`].
    ///
    /// # Conditions for validation
    ///
    /// If the transferred amount in the [`EscrowDelta`] is nil,
    /// then no keys could have been changed. If the transferred
    /// amount is greater than zero, then the appropriate escrow
    /// keys must have been written to by some wasm tx.
    #[inline]
    fn validate<TokenKeys: token::Keys>(
        &self,
        changed_keys: &BTreeSet<Key>,
    ) -> bool {
        if hints::unlikely(self.transferred_amount_is_nil()) {
            self.check_escrow_keys_unchanged::<TokenKeys>(changed_keys)
        } else {
            self.check_escrow_keys_changed::<TokenKeys>(changed_keys)
        }
    }

    /// Check if all required escrow keys in `changed_keys` were modified.
    #[inline]
    fn check_escrow_keys_changed<TokenKeys: token::Keys>(
        &self,
        changed_keys: &BTreeSet<Key>,
    ) -> bool {
        let EscrowDelta {
            token,
            payer_account,
            escrow_account,
            ..
        } = self;

        let owner_key = TokenKeys::balance_key(token, payer_account);
        let escrow_key = TokenKeys::balance_key(token, escrow_account);

        changed_keys.contains(&owner_key) && changed_keys.contains(&escrow_key)
    }

    /// Check if no escrow keys in `changed_keys` were modified.
    #[inline]
    fn check_escrow_keys_unchanged<TokenKeys: token::Keys>(
        &self,
        changed_keys: &BTreeSet<Key>,
    ) -> bool {
        let EscrowDelta {
            token,
            payer_account,
            escrow_account,
            ..
        } = self;

        let owner_key = TokenKeys::balance_key(token, payer_account);
        let escrow_key = TokenKeys::balance_key(token, escrow_account);

        !changed_keys.contains(&owner_key)
            && !changed_keys.contains(&escrow_key)
    }

    /// Check if the amount transferred to escrow is nil.
    #[inline]
    fn transferred_amount_is_nil(&self) -> bool {
        let EscrowDelta {
            transferred_amount, ..
        } = self;
        transferred_amount.is_zero()
    }
}

/// There are two checks we must do when minting wNam.
///
/// 1. Check that gas fees were escrowed.
/// 2. Check that the Nam to back wNam was escrowed.
struct EscrowCheck<'ctx> {
    gas_check: EscrowDelta<'ctx, GasCheck>,
    token_check: EscrowDelta<'ctx, TokenCheck>,
}

impl EscrowCheck<'_> {
    #[inline]
    fn validate<TokenKeys: token::Keys>(
        &self,
        changed_keys: &BTreeSet<Key>,
    ) -> bool {
        self.gas_check.validate::<TokenKeys>(changed_keys)
            && self.token_check.validate::<TokenKeys>(changed_keys)
    }
}

/// Perform a gas check.
enum GasCheck {}

/// Perform a token check.
enum TokenCheck {}

/// Sum gas and token amounts on a pending transfer, checking for overflows.
#[inline]
fn sum_gas_and_token_amounts(transfer: &PendingTransfer) -> Result<Amount> {
    transfer
        .gas_fee
        .amount
        .checked_add(transfer.transfer.amount)
        .ok_or_else(|| {
            Error::new_const(
                "Addition overflowed adding gas fee + transfer amount.",
            )
        })
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod test_bridge_pool_vp {
    use std::cell::RefCell;
    use std::env::temp_dir;

    use namada_core::address::testing::{nam, wnam};
    use namada_core::borsh::BorshSerializeExt;
    use namada_core::eth_bridge_pool::{GasFee, TransferToEthereum};
    use namada_core::hash::Hash;
    use namada_gas::{TxGasMeter, VpGasMeter};
    use namada_state::testing::{TestFullAccessState, TestState};
    use namada_state::write_log::WriteLog;
    use namada_state::{StateRead, StorageWrite, TxIndex};
    use namada_trans_token::storage_key::balance_key;
    use namada_tx::Tx;
    use namada_tx::data::TxType;
    use namada_vm::WasmCacheRwAccess;
    use namada_vm::wasm::VpCache;
    use namada_vm::wasm::run::VpEvalWasm;
    use namada_vp::native_vp;

    use super::*;
    use crate::storage::bridge_pool::get_signed_root_key;
    use crate::storage::parameters::{
        Contracts, EthereumBridgeParams, UpgradeableContract,
    };
    use crate::storage::wrapped_erc20s;

    type CA = WasmCacheRwAccess;
    type Eval<S> = VpEvalWasm<<S as StateRead>::D, <S as StateRead>::H, CA>;
    type Ctx<'ctx, S> = native_vp::Ctx<'ctx, S, VpCache<CA>, Eval<S>>;
    type TokenKeys = namada_token::Store<()>;
    type BridgePool<'ctx, S> = super::BridgePool<'ctx, Ctx<'ctx, S>, TokenKeys>;

    /// The amount of NAM Bertha has
    const ASSET: EthAddress = EthAddress([0; 20]);
    const BERTHA_WEALTH: u64 = 1_000_000;
    const BERTHA_TOKENS: u64 = 10_000;
    const DAES_NUTS: u64 = 10_000;
    const DAEWONS_GAS: u64 = 1_000_000;
    const ESCROWED_AMOUNT: u64 = 1_000;
    const ESCROWED_TOKENS: u64 = 1_000;
    const ESCROWED_NUTS: u64 = 1_000;
    const GAS_FEE: u64 = 100;
    const TOKENS: u64 = 100;

    /// A set of balances for an address
    struct Balance {
        /// The address of the Ethereum asset.
        asset: EthAddress,
        /// NUT or ERC20 Ethereum asset kind.
        kind: TransferToEthereumKind,
        /// The owner of the ERC20 assets.
        owner: Address,
        /// The gas to escrow under the Bridge pool.
        gas: Amount,
        /// The tokens to be sent across the Ethereum bridge,
        /// escrowed to the Bridge pool account.
        token: Amount,
    }

    impl Balance {
        fn new(kind: TransferToEthereumKind, address: Address) -> Self {
            Self {
                kind,
                asset: ASSET,
                owner: address,
                gas: 0.into(),
                token: 0.into(),
            }
        }
    }

    /// An established user address for testing & development
    fn bertha_address() -> Address {
        Address::decode("tnam1qyctxtpnkhwaygye0sftkq28zedf774xc5a2m7st")
            .expect("The token address decoding shouldn't fail")
    }

    /// An implicit user address for testing & development
    #[allow(dead_code)]
    pub fn daewon_address() -> Address {
        use namada_core::key::*;
        pub fn daewon_keypair() -> common::SecretKey {
            let bytes = [
                235, 250, 15, 1, 145, 250, 172, 218, 247, 27, 63, 212, 60, 47,
                164, 57, 187, 156, 182, 144, 107, 174, 38, 81, 37, 40, 19, 142,
                68, 135, 57, 50,
            ];
            let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
            ed_sk.try_to_sk().unwrap()
        }
        (&daewon_keypair().ref_to()).into()
    }

    /// A sampled established address for tests
    pub fn established_address_1() -> Address {
        Address::decode("tnam1q8j5s6xp55p05yznwnftkv3kr9gjtsw3nq7x6tw5")
            .expect("The token address decoding shouldn't fail")
    }

    /// The bridge pool at the beginning of all tests
    fn initial_pool() -> PendingTransfer {
        PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: ASSET,
                sender: bertha_address(),
                recipient: EthAddress([0; 20]),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        }
    }

    /// Create a write-log representing storage before a transfer is added to
    /// the pool.
    fn new_write_log(write_log: &mut WriteLog) {
        *write_log = WriteLog::default();
        // setup the initial bridge pool storage
        let _ = write_log
            .write(&get_signed_root_key(), Hash([0; 32]).serialize_to_vec())
            .expect("Test failed");
        let transfer = initial_pool();
        let _ = write_log
            .write(&get_pending_key(&transfer), transfer.serialize_to_vec())
            .expect("Test failed");
        // whitelist wnam
        let key = whitelist::Key {
            asset: wnam(),
            suffix: whitelist::KeyType::Whitelisted,
        }
        .into();
        let _ = write_log
            .write(&key, true.serialize_to_vec())
            .expect("Test failed");
        let key = whitelist::Key {
            asset: wnam(),
            suffix: whitelist::KeyType::Cap,
        }
        .into();
        let _ = write_log
            .write(&key, Amount::max().serialize_to_vec())
            .expect("Test failed");
        // set up users with ERC20 and NUT balances
        update_balances(
            write_log,
            Balance::new(TransferToEthereumKind::Erc20, bertha_address()),
            I320::from(BERTHA_WEALTH),
            I320::from(BERTHA_TOKENS),
        );
        update_balances(
            write_log,
            Balance::new(TransferToEthereumKind::Nut, daewon_address()),
            I320::from(DAEWONS_GAS),
            I320::from(DAES_NUTS),
        );
        // set up the initial balances of the bridge pool
        update_balances(
            write_log,
            Balance::new(TransferToEthereumKind::Erc20, BRIDGE_POOL_ADDRESS),
            I320::from(ESCROWED_AMOUNT),
            I320::from(ESCROWED_TOKENS),
        );
        update_balances(
            write_log,
            Balance::new(TransferToEthereumKind::Nut, BRIDGE_POOL_ADDRESS),
            I320::from(ESCROWED_AMOUNT),
            I320::from(ESCROWED_NUTS),
        );
        // set up the initial balances of the ethereum bridge account
        update_balances(
            write_log,
            Balance::new(TransferToEthereumKind::Erc20, BRIDGE_ADDRESS),
            I320::from(ESCROWED_AMOUNT),
            // we only care about escrowing NAM
            I320::from(0),
        );
        write_log.commit_tx_to_batch();
    }

    /// Update gas and token balances of an address and
    /// return the keys changed
    fn update_balances(
        write_log: &mut WriteLog,
        balance: Balance,
        gas_delta: I320,
        token_delta: I320,
    ) -> BTreeSet<Key> {
        // wnam is drawn from the same account
        if balance.asset == wnam()
            && !matches!(&balance.owner, Address::Internal(_))
        {
            // update the balance of nam
            let original_balance = std::cmp::max(balance.token, balance.gas);
            let updated_balance: Amount =
                (I320::from(original_balance) + gas_delta + token_delta)
                    .try_into()
                    .unwrap();

            // write the changes to the log
            let account_key = balance_key(&nam(), &balance.owner);
            let _ = write_log
                .write(&account_key, updated_balance.serialize_to_vec())
                .expect("Test failed");

            // changed keys
            [account_key].into()
        } else {
            // get the balance keys
            let token_key = if balance.asset == wnam() {
                // the match above guards against non-internal addresses,
                // so the only logical owner here is the Ethereum bridge
                // address, where we escrow NAM to, when minting wNAM on
                // Ethereum
                assert_eq!(balance.owner, BRIDGE_POOL_ADDRESS);
                balance_key(&nam(), &BRIDGE_ADDRESS)
            } else {
                balance_key(
                    &match balance.kind {
                        TransferToEthereumKind::Erc20 => {
                            wrapped_erc20s::token(&balance.asset)
                        }
                        TransferToEthereumKind::Nut => {
                            wrapped_erc20s::nut(&balance.asset)
                        }
                    },
                    &balance.owner,
                )
            };
            let account_key = balance_key(&nam(), &balance.owner);

            // update the balance of nam
            let new_gas_balance: Amount =
                (I320::from(balance.gas) + gas_delta).try_into().unwrap();

            // update the balance of tokens
            let new_token_balance: Amount = (I320::from(balance.token)
                + token_delta)
                .try_into()
                .unwrap();

            // write the changes to the log
            let _ = write_log
                .write(&account_key, new_gas_balance.serialize_to_vec())
                .expect("Test failed");
            let _ = write_log
                .write(&token_key, new_token_balance.serialize_to_vec())
                .expect("Test failed");

            // return the keys changed
            [account_key, token_key].into()
        }
    }

    /// Initialize some dummy storage for testing
    fn setup_storage() -> TestFullAccessState {
        // a dummy config for testing
        let config = EthereumBridgeParams {
            erc20_whitelist: vec![],
            eth_start_height: Default::default(),
            min_confirmations: Default::default(),
            contracts: Contracts {
                native_erc20: wnam(),
                bridge: UpgradeableContract {
                    address: EthAddress([42; 20]),
                    version: Default::default(),
                },
            },
        };
        let mut state = TestFullAccessState::default();
        let mut wl_state = state.restrict_writes_to_write_log();
        config.init_storage(&mut wl_state);
        state.commit_block().expect("Test failed");
        new_write_log(state.write_log_mut());
        state.commit_block().expect("Test failed");
        state
    }

    /// Setup a ctx for running native vps
    fn setup_ctx<'ctx>(
        tx: &'ctx Tx,
        state: &'ctx TestState,
        gas_meter: &'ctx RefCell<VpGasMeter>,
        keys_changed: &'ctx BTreeSet<Key>,
        verifiers: &'ctx BTreeSet<Address>,
    ) -> Ctx<'ctx, TestState> {
        let batched_tx = tx.batch_ref_first_tx().unwrap();
        Ctx::new(
            &BRIDGE_POOL_ADDRESS,
            state,
            batched_tx.tx,
            batched_tx.cmt,
            &TxIndex(0),
            gas_meter,
            keys_changed,
            verifiers,
            VpCache::new(temp_dir(), 100usize),
        )
    }

    enum Expect {
        Accepted,
        Rejected,
    }

    /// Helper function that tests various ways gas can be escrowed,
    /// either correctly or incorrectly, is handled appropriately
    fn assert_bridge_pool<F>(
        payer_gas_delta: I320,
        gas_escrow_delta: I320,
        payer_delta: I320,
        escrow_delta: I320,
        insert_transfer: F,
        expect: Expect,
    ) where
        F: FnOnce(&mut PendingTransfer, &mut WriteLog) -> BTreeSet<Key>,
    {
        // setup
        let mut state = setup_storage();
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();

        // the transfer to be added to the pool
        let mut transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: ASSET,
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: TOKENS.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: GAS_FEE.into(),
                payer: bertha_address(),
            },
        };
        // add transfer to pool
        let mut keys_changed =
            insert_transfer(&mut transfer, state.write_log_mut());

        // change Bertha's balances
        let mut new_keys_changed = update_balances(
            state.write_log_mut(),
            Balance {
                asset: transfer.transfer.asset,
                kind: TransferToEthereumKind::Erc20,
                owner: bertha_address(),
                gas: BERTHA_WEALTH.into(),
                token: BERTHA_TOKENS.into(),
            },
            payer_gas_delta,
            payer_delta,
        );
        keys_changed.append(&mut new_keys_changed);

        // change the bridge pool balances
        let mut new_keys_changed = update_balances(
            state.write_log_mut(),
            Balance {
                asset: transfer.transfer.asset,
                kind: TransferToEthereumKind::Erc20,
                owner: BRIDGE_POOL_ADDRESS,
                gas: ESCROWED_AMOUNT.into(),
                token: ESCROWED_TOKENS.into(),
            },
            gas_escrow_delta,
            escrow_delta,
        );
        keys_changed.append(&mut new_keys_changed);
        let verifiers = BTreeSet::default();
        // create the data to be given to the vp
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = setup_ctx(
            &tx,
            &state.restrict_writes_to_write_log(),
            &gas_meter,
            &keys_changed,
            &verifiers,
        );

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_data(transfer);

        let tx = tx.batch_ref_first_tx().unwrap();
        let res = BridgePool::validate_tx(&ctx, &tx, &keys_changed, &verifiers);
        match (expect, res) {
            (Expect::Accepted, Ok(())) => (),
            (Expect::Accepted, Err(err)) => {
                panic!("Expected VP success, but got: {err}")
            }
            (Expect::Rejected, Err(_)) => (),
            (Expect::Rejected, Ok(())) => {
                panic!("Expected VP failure, but the tx was accepted")
            }
        }
    }

    /// Test adding a transfer to the pool and escrowing gas passes vp
    #[test]
    fn test_happy_flow() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, log| {
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Accepted,
        );
    }

    /// Test that if the balance for the gas payer
    /// was not correctly adjusted, reject
    #[test]
    fn test_incorrect_gas_withdrawn() {
        assert_bridge_pool(
            -I320::from(10),
            I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, log| {
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Rejected,
        );
    }

    /// Test that if the gas payer's balance
    /// does not decrease, we reject the tx
    #[test]
    fn test_payer_balance_must_decrease() {
        assert_bridge_pool(
            I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, log| {
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Rejected,
        );
    }

    /// Test that if the gas amount escrowed is incorrect,
    /// the tx is rejected
    #[test]
    fn test_incorrect_gas_deposited() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(10),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, log| {
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Rejected,
        );
    }

    /// Test that if the number of tokens debited
    /// from one account does not equal the amount
    /// credited the other, the tx is rejected
    #[test]
    fn test_incorrect_token_deltas() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(10),
            |transfer, log| {
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Rejected,
        );
    }

    /// Test that if the number of tokens transferred
    /// is incorrect, the tx is rejected
    #[test]
    fn test_incorrect_tokens_escrowed() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            -I320::from(10),
            I320::from(10),
            |transfer, log| {
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Rejected,
        );
    }

    /// Test that the amount of gas escrowed increases,
    /// otherwise the tx is rejected.
    #[test]
    fn test_escrowed_gas_must_increase() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            -I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, log| {
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Rejected,
        );
    }

    /// Test that the amount of tokens escrowed in the
    /// bridge pool is positive.
    #[test]
    fn test_escrowed_tokens_must_increase() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            I320::from(TOKENS),
            -I320::from(TOKENS),
            |transfer, log| {
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Rejected,
        );
    }

    /// Test that if the transfer was not added to the
    /// pool, the vp rejects
    #[test]
    fn test_not_adding_transfer_rejected() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, _| BTreeSet::from([get_pending_key(transfer)]),
            Expect::Rejected,
        );
    }

    /// Test that if the wrong transaction was added
    /// to the pool, it is rejected.
    #[test]
    fn test_add_wrong_transfer() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, log| {
                let t = PendingTransfer {
                    transfer: TransferToEthereum {
                        kind: TransferToEthereumKind::Erc20,
                        asset: EthAddress([0; 20]),
                        sender: bertha_address(),
                        recipient: EthAddress([11; 20]),
                        amount: 100.into(),
                    },
                    gas_fee: GasFee {
                        token: nam(),
                        amount: GAS_FEE.into(),
                        payer: bertha_address(),
                    },
                };
                let _ = log
                    .write(&get_pending_key(transfer), t.serialize_to_vec())
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Rejected,
        );
    }

    /// Test that if the wrong transaction was added
    /// to the pool, it is rejected.
    #[test]
    fn test_add_wrong_key() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, log| {
                let t = PendingTransfer {
                    transfer: TransferToEthereum {
                        kind: TransferToEthereumKind::Erc20,
                        asset: EthAddress([0; 20]),
                        sender: bertha_address(),
                        recipient: EthAddress([11; 20]),
                        amount: 100.into(),
                    },
                    gas_fee: GasFee {
                        token: nam(),
                        amount: GAS_FEE.into(),
                        payer: bertha_address(),
                    },
                };
                let _ = log
                    .write(&get_pending_key(&t), transfer.serialize_to_vec())
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Rejected,
        );
    }

    /// Test that no tx may alter the storage containing
    /// the signed merkle root.
    #[test]
    fn test_signed_merkle_root_changes_rejected() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, log| {
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([
                    get_pending_key(transfer),
                    get_signed_root_key(),
                ])
            },
            Expect::Rejected,
        );
    }

    /// Test that adding a transfer to the pool
    /// that is already in the pool fails.
    #[test]
    fn test_adding_transfer_twice_fails() {
        // setup
        let mut state = setup_storage();
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();

        // the transfer to be added to the pool
        let transfer = initial_pool();

        // add transfer to pool
        let mut keys_changed = {
            let _ = state
                .write_log_mut()
                .write(&get_pending_key(&transfer), transfer.serialize_to_vec())
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };

        // update Bertha's balances
        let mut new_keys_changed = update_balances(
            state.write_log_mut(),
            Balance {
                asset: ASSET,
                kind: TransferToEthereumKind::Erc20,
                owner: bertha_address(),
                gas: BERTHA_WEALTH.into(),
                token: BERTHA_TOKENS.into(),
            },
            -I320::from(GAS_FEE),
            -I320::from(TOKENS),
        );
        keys_changed.append(&mut new_keys_changed);

        // update the bridge pool balances
        let mut new_keys_changed = update_balances(
            state.write_log_mut(),
            Balance {
                asset: ASSET,
                kind: TransferToEthereumKind::Erc20,
                owner: BRIDGE_POOL_ADDRESS,
                gas: ESCROWED_AMOUNT.into(),
                token: ESCROWED_TOKENS.into(),
            },
            I320::from(GAS_FEE),
            I320::from(TOKENS),
        );
        keys_changed.append(&mut new_keys_changed);
        let verifiers = BTreeSet::default();

        // create the data to be given to the vp
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = setup_ctx(
            &tx,
            &state.restrict_writes_to_write_log(),
            &gas_meter,
            &keys_changed,
            &verifiers,
        );

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_data(transfer);

        let tx = tx.batch_ref_first_tx().unwrap();
        let res = BridgePool::validate_tx(&ctx, &tx, &keys_changed, &verifiers);
        assert!(res.is_err());
    }

    /// Test that a transfer added to the pool with zero gas fees
    /// is rejected.
    #[test]
    fn test_zero_gas_fees_rejected() {
        // setup
        let mut state = setup_storage();
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: ASSET,
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // add transfer to pool
        let mut keys_changed = {
            let _ = state
                .write_log_mut()
                .write(&get_pending_key(&transfer), transfer.serialize_to_vec())
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };
        // We escrow 0 tokens
        keys_changed.insert(balance_key(
            &wrapped_erc20s::token(&ASSET),
            &bertha_address(),
        ));
        keys_changed.insert(balance_key(
            &wrapped_erc20s::token(&ASSET),
            &BRIDGE_POOL_ADDRESS,
        ));

        let verifiers = BTreeSet::default();
        // create the data to be given to the vp
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = setup_ctx(
            &tx,
            &state.restrict_writes_to_write_log(),
            &gas_meter,
            &keys_changed,
            &verifiers,
        );

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_data(transfer);

        let tx = tx.batch_ref_first_tx().unwrap();
        let res = BridgePool::validate_tx(&ctx, &tx, &keys_changed, &verifiers);
        assert!(res.is_err());
    }

    /// Test that we can escrow Nam if we
    /// want to mint wNam on Ethereum.
    #[test]
    fn test_minting_wnam() {
        // setup
        let mut state = setup_storage();
        let eb_account_key =
            balance_key(&nam(), &Address::Internal(InternalAddress::EthBridge));
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: 100.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 100.into(),
                payer: bertha_address(),
            },
        };

        // add transfer to pool
        let mut keys_changed = {
            let _ = state
                .write_log_mut()
                .write(&get_pending_key(&transfer), transfer.serialize_to_vec())
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };
        // We escrow 100 Nam into the bridge pool VP
        // and 100 Nam in the Eth bridge VP
        let account_key = balance_key(&nam(), &bertha_address());
        let _ = state
            .write_log_mut()
            .write(
                &account_key,
                Amount::from(BERTHA_WEALTH - 200).serialize_to_vec(),
            )
            .expect("Test failed");
        assert!(keys_changed.insert(account_key));
        let bp_account_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        let _ = state
            .write_log_mut()
            .write(
                &bp_account_key,
                Amount::from(ESCROWED_AMOUNT + 100).serialize_to_vec(),
            )
            .expect("Test failed");
        assert!(keys_changed.insert(bp_account_key));
        let _ = state
            .write_log_mut()
            .write(
                &eb_account_key,
                Amount::from(ESCROWED_AMOUNT + 100).serialize_to_vec(),
            )
            .expect("Test failed");
        assert!(keys_changed.insert(eb_account_key));

        let verifiers = BTreeSet::default();
        // create the data to be given to the vp
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = setup_ctx(
            &tx,
            &state.restrict_writes_to_write_log(),
            &gas_meter,
            &keys_changed,
            &verifiers,
        );

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_data(transfer);

        let tx = tx.batch_ref_first_tx().unwrap();
        let res = BridgePool::validate_tx(&ctx, &tx, &keys_changed, &verifiers);
        assert!(res.is_ok());
    }

    /// Test that we can reject a transfer that
    /// mints wNam if we don't escrow the correct
    /// amount of Nam.
    #[test]
    fn test_reject_mint_wnam() {
        // setup
        let mut state = setup_storage();
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();
        let eb_account_key =
            balance_key(&nam(), &Address::Internal(InternalAddress::EthBridge));

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: 100.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 100.into(),
                payer: bertha_address(),
            },
        };

        // add transfer to pool
        let keys_changed = {
            let _ = state
                .write_log_mut()
                .write(&get_pending_key(&transfer), transfer.serialize_to_vec())
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };
        // We escrow 100 Nam into the bridge pool VP
        // and 100 Nam in the Eth bridge VP
        let account_key = balance_key(&nam(), &bertha_address());
        let _ = state
            .write_log_mut()
            .write(
                &account_key,
                Amount::from(BERTHA_WEALTH - 200).serialize_to_vec(),
            )
            .expect("Test failed");
        let bp_account_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        let _ = state
            .write_log_mut()
            .write(
                &bp_account_key,
                Amount::from(ESCROWED_AMOUNT + 100).serialize_to_vec(),
            )
            .expect("Test failed");
        let _ = state
            .write_log_mut()
            .write(&eb_account_key, Amount::from(10).serialize_to_vec())
            .expect("Test failed");
        let verifiers = BTreeSet::default();

        // create the data to be given to the vp
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = setup_ctx(
            &tx,
            &state.restrict_writes_to_write_log(),
            &gas_meter,
            &keys_changed,
            &verifiers,
        );

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_data(transfer);

        let tx = tx.batch_ref_first_tx().unwrap();
        let res = BridgePool::validate_tx(&ctx, &tx, &keys_changed, &verifiers);
        assert!(res.is_err());
    }

    /// Test that we check escrowing Nam correctly when minting wNam
    /// and the gas payer account is different from the transferring
    /// account.
    #[test]
    fn test_mint_wnam_separate_gas_payer() {
        // setup
        let mut state = setup_storage();
        let mut wl_state = state.restrict_writes_to_write_log();
        // initialize the eth bridge balance to 0
        let eb_account_key =
            balance_key(&nam(), &Address::Internal(InternalAddress::EthBridge));
        wl_state
            .write(&eb_account_key, Amount::default())
            .expect("Test failed");
        // initialize the gas payers account
        let gas_payer_balance_key =
            balance_key(&nam(), &established_address_1());
        wl_state
            .write(&gas_payer_balance_key, Amount::from(BERTHA_WEALTH))
            .expect("Test failed");
        wl_state.write_log_mut().commit_tx_to_batch();
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: wnam(),
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: 100.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 100.into(),
                payer: established_address_1(),
            },
        };

        // add transfer to pool
        let keys_changed = {
            let _ = wl_state
                .write(&get_pending_key(&transfer), transfer.serialize_to_vec())
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };
        // We escrow 100 Nam into the bridge pool VP
        // and 100 Nam in the Eth bridge VP
        let account_key = balance_key(&nam(), &bertha_address());
        let _ = wl_state
            .write(
                &account_key,
                Amount::from(BERTHA_WEALTH - 100).serialize_to_vec(),
            )
            .expect("Test failed");
        let _ = wl_state
            .write(
                &gas_payer_balance_key,
                Amount::from(BERTHA_WEALTH - 100).serialize_to_vec(),
            )
            .expect("Test failed");
        let bp_account_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        let _ = wl_state
            .write(
                &bp_account_key,
                Amount::from(ESCROWED_AMOUNT + 100).serialize_to_vec(),
            )
            .expect("Test failed");
        let _ = wl_state
            .write(&eb_account_key, Amount::from(10).serialize_to_vec())
            .expect("Test failed");
        let verifiers = BTreeSet::default();
        // create the data to be given to the vp
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = setup_ctx(
            &tx,
            &wl_state,
            &gas_meter,
            &keys_changed,
            &verifiers,
        );

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_data(transfer);

        let tx = tx.batch_ref_first_tx().unwrap();
        let res = BridgePool::validate_tx(&ctx, &tx, &keys_changed, &verifiers);
        assert!(res.is_err());
    }

    /// Auxiliary function to test NUT functionality.
    fn test_nut_aux(kind: TransferToEthereumKind, expect: Expect) {
        // setup
        let mut state = setup_storage();
        let mut wl_state = state.restrict_writes_to_write_log();
        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind,
                asset: ASSET,
                sender: daewon_address(),
                recipient: EthAddress([1; 20]),
                amount: TOKENS.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: GAS_FEE.into(),
                payer: daewon_address(),
            },
        };

        // add transfer to pool
        let mut keys_changed = {
            let _ = wl_state
                .write(&get_pending_key(&transfer), transfer.serialize_to_vec())
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };

        // update Daewon's balances
        let mut new_keys_changed = update_balances(
            wl_state.write_log_mut(),
            Balance {
                kind,
                asset: ASSET,
                owner: daewon_address(),
                gas: DAEWONS_GAS.into(),
                token: DAES_NUTS.into(),
            },
            -I320::from(GAS_FEE),
            -I320::from(TOKENS),
        );
        keys_changed.append(&mut new_keys_changed);

        // change the bridge pool balances
        let mut new_keys_changed = update_balances(
            wl_state.write_log_mut(),
            Balance {
                kind,
                asset: ASSET,
                owner: BRIDGE_POOL_ADDRESS,
                gas: ESCROWED_AMOUNT.into(),
                token: ESCROWED_NUTS.into(),
            },
            I320::from(GAS_FEE),
            I320::from(TOKENS),
        );
        keys_changed.append(&mut new_keys_changed);

        // create the data to be given to the vp
        let verifiers = BTreeSet::default();
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(u64::MAX, 1),
        ));
        let ctx = setup_ctx(
            &tx,
            &wl_state,
            &gas_meter,
            &keys_changed,
            &verifiers,
        );

        let mut tx = Tx::from_type(TxType::Raw);
        tx.push_default_inner_tx();
        tx.add_data(transfer);

        let tx = tx.batch_ref_first_tx().unwrap();
        let res = BridgePool::validate_tx(&ctx, &tx, &keys_changed, &verifiers);
        match (expect, res) {
            (Expect::Accepted, Ok(())) => (),
            (Expect::Accepted, Err(err)) => {
                panic!("Expected VP success, but got: {err}")
            }
            (Expect::Rejected, Err(_)) => (),
            (Expect::Rejected, Ok(())) => {
                panic!("Expected VP failure, but the tx was accepted")
            }
        }
    }

    /// Test that the Bridge pool VP rejects a tx based on the fact
    /// that an account might hold NUTs of some arbitrary Ethereum
    /// asset, but not hold ERC20s.
    #[test]
    fn test_reject_no_erc20_balance_despite_nut_balance() {
        test_nut_aux(TransferToEthereumKind::Erc20, Expect::Rejected)
    }

    /// Test the happy flow of escrowing NUTs.
    #[test]
    fn test_escrowing_nuts_happy_flow() {
        test_nut_aux(TransferToEthereumKind::Nut, Expect::Accepted)
    }

    /// Test that the Bridge pool VP rejects a wNAM NUT transfer.
    #[test]
    fn test_bridge_pool_vp_rejects_wnam_nut() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, log| {
                transfer.transfer.kind = TransferToEthereumKind::Nut;
                transfer.transfer.asset = wnam();
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Rejected,
        );
    }

    /// Test that the Bridge pool VP accepts a wNAM ERC20 transfer.
    #[test]
    fn test_bridge_pool_vp_accepts_wnam_erc20() {
        assert_bridge_pool(
            -I320::from(GAS_FEE),
            I320::from(GAS_FEE),
            -I320::from(TOKENS),
            I320::from(TOKENS),
            |transfer, log| {
                transfer.transfer.kind = TransferToEthereumKind::Erc20;
                transfer.transfer.asset = wnam();
                let _ = log
                    .write(
                        &get_pending_key(transfer),
                        transfer.serialize_to_vec(),
                    )
                    .unwrap();
                BTreeSet::from([get_pending_key(transfer)])
            },
            Expect::Accepted,
        );
    }

    /// Test that the Bridge pool native VP validates transfers that
    /// do not contain gas fees and no associated changed keys.
    #[test]
    fn test_no_gas_fees_with_no_changed_keys() {
        let nam_addr = nam();
        let delta = EscrowDelta {
            token: Cow::Borrowed(&nam_addr),
            payer_account: &bertha_address(),
            escrow_account: &BRIDGE_ADDRESS,
            expected_debit: Amount::zero(),
            expected_credit: Amount::zero(),
            // NOTE: testing 0 amount
            transferred_amount: &Amount::zero(),
            // NOTE: testing gas fees
            _kind: PhantomData::<*const GasCheck>,
        };
        // NOTE: testing no changed keys
        let empty_keys = BTreeSet::new();

        assert!(delta.validate::<TokenKeys>(&empty_keys));
    }

    /// Test that the Bridge pool native VP rejects transfers that
    /// do not contain gas fees and has associated changed keys.
    #[test]
    fn test_no_gas_fees_with_changed_keys() {
        let nam_addr = nam();
        let delta = EscrowDelta {
            token: Cow::Borrowed(&nam_addr),
            payer_account: &bertha_address(),
            escrow_account: &BRIDGE_ADDRESS,
            expected_debit: Amount::zero(),
            expected_credit: Amount::zero(),
            // NOTE: testing 0 amount
            transferred_amount: &Amount::zero(),
            // NOTE: testing gas fees
            _kind: PhantomData::<*const GasCheck>,
        };
        let owner_key = balance_key(&nam_addr, &bertha_address());
        // NOTE: testing changed keys
        let some_changed_keys = BTreeSet::from([owner_key]);

        assert!(!delta.validate::<TokenKeys>(&some_changed_keys));
    }

    /// Test that the Bridge pool native VP validates transfers
    /// moving no value and with no associated changed keys.
    #[test]
    fn test_no_amount_with_no_changed_keys() {
        let nam_addr = nam();
        let delta = EscrowDelta {
            token: Cow::Borrowed(&nam_addr),
            payer_account: &bertha_address(),
            escrow_account: &BRIDGE_ADDRESS,
            expected_debit: Amount::zero(),
            expected_credit: Amount::zero(),
            // NOTE: testing 0 amount
            transferred_amount: &Amount::zero(),
            // NOTE: testing token transfers
            _kind: PhantomData::<*const TokenCheck>,
        };
        // NOTE: testing no changed keys
        let empty_keys = BTreeSet::new();

        assert!(delta.validate::<TokenKeys>(&empty_keys));
    }

    /// Test that the Bridge pool native VP rejects transfers
    /// moving no value and with associated changed keys.
    #[test]
    fn test_no_amount_with_changed_keys() {
        let nam_addr = nam();
        let delta = EscrowDelta {
            token: Cow::Borrowed(&nam_addr),
            payer_account: &bertha_address(),
            escrow_account: &BRIDGE_ADDRESS,
            expected_debit: Amount::zero(),
            expected_credit: Amount::zero(),
            // NOTE: testing 0 amount
            transferred_amount: &Amount::zero(),
            // NOTE: testing token transfers
            _kind: PhantomData::<*const TokenCheck>,
        };
        let owner_key = balance_key(&nam_addr, &bertha_address());
        // NOTE: testing changed keys
        let some_changed_keys = BTreeSet::from([owner_key]);

        assert!(!delta.validate::<TokenKeys>(&some_changed_keys));
    }
}
