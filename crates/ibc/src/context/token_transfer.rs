//! IBC token transfer context

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::rc::Rc;

use bitflags::bitflags;
use ibc::apps::transfer::context::{
    TokenTransferExecutionContext, TokenTransferValidationContext,
};
use ibc::apps::transfer::types::error::TokenTransferError;
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use ibc::apps::transfer::types::{Memo, PrefixedCoin, PrefixedDenom};
use ibc::core::host::types::error::HostError;
use ibc::core::host::types::identifiers::{ChannelId, PortId};
use ibc::core::primitives::Signer;
use namada_core::address::{Address, InternalAddress, MASP, PGF};
use namada_core::arith::{CheckedAdd, checked};
use namada_core::masp::{AssetData, CompactNote, PaymentAddress};
use namada_core::token::{Amount, MaspDigitPos};
use namada_core::uint::Uint;
use namada_state::StorageRead;
use namada_tx::event::{MaspEvent, MaspEventKind, MaspTxRef};

use super::common::IbcCommonContext;
use crate::context::middlewares::MaspUnshieldingFeesExecutionContext;
use crate::context::storage::IbcStorageContext;
use crate::storage::{load_shielding_counter, write_shielding_counter};
use crate::{IBC_ESCROW_ADDRESS, IbcAccountId, trace};

bitflags! {
    #[derive(
        Debug, Clone, Copy,
    )]
    struct TokenTransferContextConfig: u8 {
        const HAS_MASP_TX = 0b1;
        const IS_REFUND = 0b10;
    }
}

/// Token transfer context to handle tokens
#[derive(Debug)]
pub struct TokenTransferContext<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext,
{
    pub(crate) inner: Rc<RefCell<C>>,
    pub(crate) verifiers: Rc<RefCell<BTreeSet<Address>>>,
    config: TokenTransferContextConfig,
    _marker: PhantomData<(Params, Token, ShieldedToken)>,
}

impl<C, Params, Token, ShieldedToken>
    TokenTransferContext<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext,
{
    /// Make new token transfer context
    pub fn new(
        inner: Rc<RefCell<C>>,
        verifiers: Rc<RefCell<BTreeSet<Address>>>,
    ) -> Self {
        Self {
            inner,
            verifiers,
            config: TokenTransferContextConfig::empty(),
            _marker: PhantomData,
        }
    }

    /// Insert a verifier address whose VP will verify the tx.
    pub(crate) fn insert_verifier(&self, addr: &Address) {
        self.verifiers.borrow_mut().insert(addr.clone());
    }

    /// Set to enable a shielded transfer
    pub fn enable_shielded_transfer(&mut self) {
        self.config
            .set(TokenTransferContextConfig::HAS_MASP_TX, true);
    }

    /// Set the transfer as refund
    pub fn enable_refund_transfer(&mut self) {
        self.config.set(TokenTransferContextConfig::IS_REFUND, true);
    }

    fn validate_sent_coin(&self, coin: &PrefixedCoin) -> Result<(), HostError> {
        // The base denom should not be an IBC token address because an IBC
        // token address has been already encoded and other chains can't extract
        // the trace paths
        match Address::decode(coin.denom.base_denom.as_str()) {
            Ok(Address::Internal(InternalAddress::IbcToken(_))) => {
                Err(HostError::Other {
                    description: "The base denom should not be an IBC token \
                                  address"
                        .to_string(),
                })
            }
            _ => Ok(()),
        }
    }

    /// Update the mint amount of the token
    fn update_mint_amount(
        &self,
        token: &Address,
        amount: Amount,
        is_minted: bool,
    ) -> Result<(), HostError> {
        let mint = self.inner.borrow().mint_amount(token)?;
        let updated_mint = if is_minted {
            mint.checked_add(amount).ok_or_else(|| HostError::Other {
                description: "The mint amount overflowed".to_string(),
            })?
        } else {
            mint.checked_sub(amount).ok_or_else(|| HostError::Other {
                description: "The mint amount underflowed".to_string(),
            })?
        };
        self.inner
            .borrow_mut()
            .store_mint_amount(token, updated_mint)
    }

    /// Add the amount to the per-epoch withdraw of the token
    fn increment_per_epoch_deposit_limits(
        &self,
        token: &Address,
        amount: Amount,
    ) -> Result<(), HostError> {
        let is_refund =
            self.config.contains(TokenTransferContextConfig::IS_REFUND);
        if is_refund {
            return Ok(());
        }
        let deposit = self.inner.borrow().deposit(token)?;
        let added_deposit =
            deposit
                .checked_add(amount)
                .ok_or_else(|| HostError::Other {
                    description: "The per-epoch deposit overflowed".to_string(),
                })?;
        self.inner
            .borrow_mut()
            .store_deposit(token, added_deposit)?;
        Ok(())
    }

    /// Add the amount to the per-epoch withdraw of the token
    fn increment_per_epoch_withdraw_limits(
        &self,
        token: &Address,
        amount: Amount,
    ) -> Result<(), HostError> {
        let withdraw = self.inner.borrow().withdraw(token)?;
        let added_withdraw =
            withdraw
                .checked_add(amount)
                .ok_or_else(|| HostError::Other {
                    description: "The per-epoch withdraw overflowed"
                        .to_string(),
                })?;
        self.inner
            .borrow_mut()
            .store_withdraw(token, added_withdraw)
    }

    fn maybe_store_ibc_denom(
        &self,
        owner: &Address,
        coin: &PrefixedCoin,
    ) -> Result<(), HostError> {
        if coin.denom.trace_path.is_empty() {
            // It isn't an IBC denom
            return Ok(());
        }
        let ibc_denom = coin.denom.to_string();
        let trace_hash = trace::calc_hash(&ibc_denom);

        self.inner.borrow_mut().store_ibc_trace(
            owner.to_string(),
            &trace_hash,
            &ibc_denom,
        )
    }

    #[inline]
    fn maybe_handle_masp_memoless_shielding<F>(
        &self,
        to_account: &IbcAccountId,
        token: &Address,
        amount: &Amount,
        transfer: F,
    ) -> Result<Amount, HostError>
    where
        F: FnOnce(Amount) -> Result<(), HostError>,
        Params:
            namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
        Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>,
        ShieldedToken: namada_systems::shielded_token::Write<
                <C as IbcStorageContext>::Storage,
            >,
    {
        let mut amount = *amount;

        if let IbcAccountId::Shielded(owner_pa) = to_account {
            if let Some(fee) = self.get_masp_shielding_fee(token, &amount)? {
                amount = amount.checked_sub(fee).ok_or_else(|| {
                    HostError::Other {
                        description: "Shielding fee greater than deposited \
                                      amount"
                            .to_string(),
                    }
                })?;

                transfer(fee)?;
            }

            self.store_masp_note_commitments(owner_pa, token, &amount)?;
        }

        Ok(amount)
    }

    #[inline]
    fn maybe_handle_masp_unshielding(
        &self,
        from_account: &IbcAccountId,
    ) -> Result<(), HostError> {
        let has_masp_tx = self
            .config
            .contains(TokenTransferContextConfig::HAS_MASP_TX);

        if !has_masp_tx && from_account.is_shielded() {
            return Err(HostError::Other {
                description: format!(
                    "Set refund address {from_account} without including an \
                     IBC unshielding MASP transaction"
                ),
            });
        }

        Ok(())
    }

    fn get_masp_shielding_fee(
        &self,
        token: &Address,
        amount: &Amount,
    ) -> Result<Option<Amount>, HostError>
    where
        Params:
            namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
    {
        let is_refund =
            self.config.contains(TokenTransferContextConfig::IS_REFUND);

        if is_refund {
            return Ok(None);
        }

        let Some(fee_percentage) = Params::ibc_shielding_fee_percentage(
            self.inner.borrow().storage(),
            token,
        )?
        else {
            return Ok(None);
        };

        Ok(Some(amount.checked_mul_dec(fee_percentage).ok_or_else(
            || HostError::Other {
                description:
                    "Overflow in MASP shielding fee computation".to_string(),
            },
        )?))
    }

    fn get_masp_unshielding_fee(
        &self,
        token: &Address,
        amount: &Amount,
    ) -> Result<Option<Amount>, HostError>
    where
        Params:
            namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
    {
        get_masp_unshielding_fee::<_, Params>(
            self.inner.borrow().storage(),
            token,
            amount,
        )
    }

    fn store_masp_note_commitments(
        &self,
        owner_pa: &PaymentAddress,
        token: &Address,
        amount: &Amount,
    ) -> Result<(), HostError>
    where
        Params:
            namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
        Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>,
        ShieldedToken: namada_systems::shielded_token::Write<
                <C as IbcStorageContext>::Storage,
            >,
    {
        use namada_events::extend::ComposeEvent;
        use namada_tx::event::ProtocolIbcShielding;

        if amount.is_zero() {
            return Ok(());
        }

        let mut notes = vec![];
        let mut note_commitments = vec![];

        let mut next_shielding_counter = load_shielding_counter(
            self.inner.borrow().storage(),
        )
        .map_err(|err| HostError::Other {
            description: format!(
                "Failed to load IBC shielding counter from storage: {err}"
            ),
        })?;

        let denom = Token::read_denom(self.inner.borrow().storage(), token)
            .map_err(|err| HostError::Other {
                description: format!(
                    "Failed to read token denom of {token}: {err}"
                ),
            })?
            .ok_or_else(|| HostError::Other {
                description: format!("No token denom in storage for {token}"),
            })?;

        let epoched_asset = {
            let masp_epoch = {
                let current_epoch =
                    self.inner.borrow().storage().get_block_epoch()?;
                Params::masp_epoch(
                    self.inner.borrow().storage(),
                    current_epoch,
                )?
            };
            let asset = AssetData {
                token: token.clone(),
                denom,
                // NB: assume there are conversions for all
                // other digit positions
                position: MaspDigitPos::Zero,
                epoch: Some(masp_epoch),
            };
            let asset_type = asset.encode().map_err(|_| HostError::Other {
                description: format!(
                    "Failed to create asset type of IBC shielding: {asset:?}"
                ),
            })?;

            // NB: attribute an epoch to the asset so that
            // it can earn rewards, assuming it has conversions
            // in the conversion state at the current masp epoch
            self.inner
                .borrow()
                .has_conversion(&asset_type)?
                .then_some(masp_epoch)
        };

        for (digit, note_value) in MaspDigitPos::iter()
            .zip(amount.iter_words())
            .filter(|(_, word)| *word != 0u64)
        {
            let asset = AssetData {
                token: token.clone(),
                denom,
                position: digit,
                epoch: epoched_asset,
            };
            let asset_type = asset.encode().map_err(|_| HostError::Other {
                description: format!(
                    "Failed to create asset type of IBC shielding: {asset:?}"
                ),
            })?;

            let rseed = namada_core::hash::Hash::sha256(format!(
                "Namada IBC shielding {next_shielding_counter}"
            ))
            .0;

            checked!(next_shielding_counter += 1).map_err(|_err| {
                HostError::Other {
                    description: "Arithmetic overflow in IBC shielding \
                                  counter increment"
                        .to_string(),
                }
            })?;

            let note = owner_pa
                .create_note(asset_type, note_value, rseed)
                .ok_or_else(|| HostError::Other {
                    description: format!(
                        "Invalid payment address used to mint note: {owner_pa}"
                    ),
                })?;

            note_commitments.push(note.commitment());
            notes.push(
                CompactNote::new(note, (*owner_pa).into())
                    .expect("The payment address has already been validated"),
            );
        }

        write_shielding_counter(
            self.inner.borrow_mut().storage_mut(),
            next_shielding_counter,
        )
        .map_err(|err| HostError::Other {
            description: format!(
                "Failed to write IBC shielding counter to storage: {err}"
            ),
        })?;

        let tx_index = self
            .inner
            .borrow()
            .storage()
            .get_tx_index()
            .map_err(|err| HostError::Other {
                description: format!("Failed to read tx index: {err}"),
            })?
            .into();
        self.inner.borrow_mut().emit_event(
            MaspEvent {
                tx_index,
                kind: MaspEventKind::Transfer,
                data: MaspTxRef::Unencrypted(notes),
            }
            .with(ProtocolIbcShielding)
            .into(),
        )?;

        // update the undated asset balance
        if epoched_asset.is_none() {
            let current_amount = ShieldedToken::read_undated_balance(
                self.inner.borrow().storage(),
                token,
            )
            .map_err(|err| HostError::Other {
                description: format!(
                    "Failed to read undated asset balance of {token}: {err}"
                ),
            })?;

            ShieldedToken::write_undated_balance(
                self.inner.borrow_mut().storage_mut(),
                token,
                current_amount.checked_add(*amount).ok_or_else(|| {
                    HostError::Other {
                        description: format!(
                            "Arithmetic overflow in IBC shielding undated \
                             asset balance increment of {token}",
                        ),
                    }
                })?,
            )
            .map_err(|err| HostError::Other {
                description: format!(
                    "Failed to write undated asset balance of {token}: {err}"
                ),
            })?;
        }

        ShieldedToken::update_commitment_tree(
            self.inner.borrow_mut().storage_mut(),
            note_commitments,
        )
        .map_err(HostError::from)
    }
}

impl<C, Params, Token, ShieldedToken> TokenTransferValidationContext
    for TokenTransferContext<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext,
{
    type AccountId = IbcAccountId;

    fn sender_account(
        &self,
        signer: &Signer,
    ) -> Result<Self::AccountId, HostError> {
        signer.as_ref().parse()
    }

    fn receiver_account(
        &self,
        signer: &Signer,
    ) -> Result<Self::AccountId, HostError> {
        signer.as_ref().parse()
    }

    fn get_port(&self) -> Result<PortId, HostError> {
        Ok(PortId::transfer())
    }

    fn can_send_coins(&self) -> Result<(), HostError> {
        Ok(())
    }

    fn can_receive_coins(&self) -> Result<(), HostError> {
        Ok(())
    }

    fn escrow_coins_validate(
        &self,
        _from_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), HostError> {
        self.validate_sent_coin(coin)?;

        // validated by Multitoken VP
        Ok(())
    }

    fn unescrow_coins_validate(
        &self,
        _to_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        _coin: &PrefixedCoin,
    ) -> Result<(), HostError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn mint_coins_validate(
        &self,
        _account: &Self::AccountId,
        _coin: &PrefixedCoin,
    ) -> Result<(), HostError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn burn_coins_validate(
        &self,
        _account: &Self::AccountId,
        coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), HostError> {
        self.validate_sent_coin(coin)?;

        // validated by Multitoken VP
        Ok(())
    }

    fn denom_hash_string(&self, denom: &PrefixedDenom) -> Option<String> {
        Some(trace::calc_hash(denom.to_string()))
    }
}

impl<C, Params, Token, ShieldedToken> TokenTransferExecutionContext
    for TokenTransferContext<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
    ShieldedToken: namada_systems::shielded_token::Write<<C as IbcStorageContext>::Storage>,
    Token: namada_systems::trans_token::Read<<C as IbcStorageContext>::Storage>,
{
    fn escrow_coins_execute(
        &mut self,
        from_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), HostError> {
        let (ibc_token, amount) = get_token_amount(coin)?;
        let has_masp_tx = self
            .config
            .contains(TokenTransferContextConfig::HAS_MASP_TX);

        let from_trans_account = if has_masp_tx {
            Cow::Owned(MASP)
        } else {
            from_account.to_address()
        };

        self.maybe_handle_masp_unshielding(from_account)?;

        self.increment_per_epoch_withdraw_limits(&ibc_token, amount)?;

        // A transfer of NUT tokens must be verified by their VP
        if ibc_token.is_internal()
            && matches!(ibc_token, Address::Internal(InternalAddress::Nut(_)))
        {
            self.insert_verifier(&ibc_token);
        }

        self.inner
            .borrow_mut()
            .transfer_token(
                &from_trans_account,
                &IBC_ESCROW_ADDRESS,
                &ibc_token,
                amount,
            )
            .map_err(HostError::from)
    }

    fn unescrow_coins_execute(
        &mut self,
        to_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        coin: &PrefixedCoin,
    ) -> Result<(), HostError> {
        let (ibc_token, amount) = get_token_amount(coin)?;

        let amount = self.maybe_handle_masp_memoless_shielding(
            to_account,
            &ibc_token,
            &amount,
            |fee| {
                self.insert_verifier(&PGF);
                self.inner
                    .borrow_mut()
                    .transfer_token(&IBC_ESCROW_ADDRESS, &PGF, &ibc_token, fee)
                    .map_err(HostError::from)
            },
        )?;

        self.increment_per_epoch_deposit_limits(&ibc_token, amount)?;

        self.inner
            .borrow_mut()
            .transfer_token(
                &IBC_ESCROW_ADDRESS,
                &to_account.to_address(),
                &ibc_token,
                amount,
            )
            .map_err(HostError::from)
    }

    fn mint_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), HostError> {
        // The trace path of the denom is already updated if receiving the token
        let (ibc_token, amount) = get_token_amount(coin)?;

        // NOTE: update the minted amount before paying for
        // shielding fees, since the fees are also minted
        self.update_mint_amount(&ibc_token, amount, true)?;

        let amount = self.maybe_handle_masp_memoless_shielding(
            account,
            &ibc_token,
            &amount,
            |fee| {
                self.insert_verifier(&PGF);
                self.inner
                    .borrow_mut()
                    .mint_token(&PGF, &ibc_token, fee)
                    .map_err(HostError::from)
            },
        )?;

        self.increment_per_epoch_deposit_limits(&ibc_token, amount)?;

        // A transfer of NUT tokens must be verified by their VP
        if ibc_token.is_internal()
            && matches!(ibc_token, Address::Internal(InternalAddress::Nut(_)))
        {
            self.insert_verifier(&ibc_token);
        }

        let account = account.to_address();

        // Store the IBC denom with the token hash to be able to retrieve it
        // later
        self.maybe_store_ibc_denom(&account, coin)?;

        self.inner
            .borrow_mut()
            .mint_token(&account, &ibc_token, amount)
            .map_err(HostError::from)
    }

    fn burn_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), HostError> {
        let (ibc_token, amount) = get_token_amount(coin)?;
        let has_masp_tx = self
            .config
            .contains(TokenTransferContextConfig::HAS_MASP_TX);

        let trans_account = if has_masp_tx {
            Cow::Owned(MASP)
        } else {
            account.to_address()
        };

        self.maybe_handle_masp_unshielding(account)?;

        self.update_mint_amount(&ibc_token, amount, false)?;

        self.increment_per_epoch_withdraw_limits(&ibc_token, amount)?;

        // A transfer of NUT tokens must be verified by their VP
        if ibc_token.is_internal()
            && matches!(ibc_token, Address::Internal(InternalAddress::Nut(_)))
        {
            self.insert_verifier(&ibc_token);
        }

        // The burn is "unminting" from the minted balance
        self.inner
            .borrow_mut()
            .burn_token(&trans_account, &ibc_token, amount)
            .map_err(HostError::from)
    }
}

/// Get the token address and the amount from PrefixedCoin. If the base
/// denom is not an address, it returns `IbcToken`
fn get_token_amount(
    coin: &PrefixedCoin,
) -> Result<(Address, Amount), HostError> {
    let token = match Address::decode(coin.denom.base_denom.as_str()) {
        Ok(token_addr) if coin.denom.trace_path.is_empty() => token_addr,
        _ => trace::ibc_token(coin.denom.to_string()),
    };

    // Convert IBC amount to Namada amount for the token
    let uint_amount = Uint(primitive_types::U256::from(coin.amount).0);
    let amount =
        Amount::from_uint(uint_amount, 0).map_err(|e| HostError::Other {
            description: format!(
                "The IBC amount is invalid: Coin {coin}, Error {e}",
            ),
        })?;

    Ok((token, amount))
}

fn get_masp_unshielding_fee<S, Params>(
    storage: &S,
    token: &Address,
    amount: &Amount,
) -> Result<Option<Amount>, HostError>
where
    Params: namada_systems::parameters::Read<S>,
{
    let Some(fee_percentage) =
        Params::ibc_unshielding_fee_percentage(storage, token)?
    else {
        return Ok(None);
    };

    Ok(Some(amount.checked_mul_dec(fee_percentage).ok_or_else(
        || HostError::Other {
            description:
                "Overflow in MASP unshielding fee computation".to_string(),
        },
    )?))
}

#[allow(missing_docs)]
pub struct ParamsStorageAdapter<S, Params>(S, PhantomData<Params>);

impl<S, Params> ParamsStorageAdapter<S, Params> {
    #[allow(missing_docs)]
    pub const fn adapt(storage: S) -> Self {
        Self(storage, PhantomData)
    }
}

impl<S, Params> MaspUnshieldingFeesExecutionContext<crate::IbcTransferInfo>
    for ParamsStorageAdapter<S, Params>
where
    Params: namada_systems::parameters::Read<S>,
{
    fn apply_masp_unshielding_fee(
        &self,
        msg: &mut crate::IbcTransferInfo,
    ) -> Result<(), TokenTransferError> {
        for trace in msg.ibc_traces.iter() {
            let ibc_token =
                crate::trace::convert_to_address(trace).map_err(|err| {
                    HostError::Other {
                        description: format!(
                            "Failed to convert {trace:?} to address: {err}"
                        ),
                    }
                })?;

            if let Some(fee) = get_masp_unshielding_fee::<_, Params>(
                &self.0,
                &ibc_token,
                &msg.amount,
            )
            .map_err(TokenTransferError::Host)?
            .filter(|fee| !fee.is_zero())
            {
                msg.amount =
                    // NOTE: we're adding the fee, because we want to recreate the
                    // original packet
                    msg.amount.checked_add(fee).ok_or_else(|| HostError::Other {
                        description: "Unshielding fee greater than withdrawn \
                                      amount"
                            .to_string(),
                    })?;
            }
        }

        Ok(())
    }
}

impl<C, Params, Token, ShieldedToken>
    MaspUnshieldingFeesExecutionContext<MsgTransfer>
    for TokenTransferContext<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
{
    fn apply_masp_unshielding_fee(
        &self,
        msg: &mut MsgTransfer,
    ) -> Result<(), TokenTransferError> {
        // no fee is taken if this is not a masp unshielding op
        let has_masp_tx = self
            .config
            .contains(TokenTransferContextConfig::HAS_MASP_TX);
        if !has_masp_tx {
            return Ok(());
        }

        let (ibc_token, mut amount) = get_token_amount(&msg.packet_data.token)
            .map_err(TokenTransferError::Host)?;

        if let Some(fee) = self
            .get_masp_unshielding_fee(&ibc_token, &amount)
            .map_err(TokenTransferError::Host)?
            .filter(|fee| !fee.is_zero())
        {
            amount =
                amount.checked_sub(fee).ok_or_else(|| HostError::Other {
                    description: "Unshielding fee greater than withdrawn \
                                  amount"
                        .to_string(),
                })?;

            // commit the updated amount to the packet
            msg.packet_data.token.amount = amount.into();

            // transfer the fee to PGF, and trigger its vp
            self.insert_verifier(&PGF);
            self.inner
                .borrow_mut()
                .transfer_token(&MASP, &PGF, &ibc_token, fee)
                .map_err(HostError::from)
                .map_err(TokenTransferError::Host)?;
        }

        Ok(())
    }
}
