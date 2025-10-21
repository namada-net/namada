//! IBC token transfer context

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::rc::Rc;

use ibc::apps::transfer::context::{
    TokenTransferExecutionContext, TokenTransferValidationContext,
};
use ibc::apps::transfer::types::{Memo, PrefixedCoin, PrefixedDenom};
use ibc::core::host::types::error::HostError;
use ibc::core::host::types::identifiers::{ChannelId, PortId};
use ibc::core::primitives::Signer;
use namada_core::address::{Address, InternalAddress, MASP};
use namada_core::arith::{CheckedAdd, checked};
use namada_core::masp::{AssetData, PaymentAddress};
use namada_core::token::{Amount, MaspDigitPos};
use namada_core::uint::Uint;

use super::common::IbcCommonContext;
use crate::context::storage::IbcStorageContext;
use crate::storage::{load_shielding_counter, write_shielding_counter};
use crate::{IBC_ESCROW_ADDRESS, trace};

/// Token transfer context to handle tokens
#[derive(Debug)]
pub struct TokenTransferContext<C, Params, Token, ShieldedToken>
where
    C: IbcCommonContext,
{
    pub(crate) inner: Rc<RefCell<C>>,
    pub(crate) verifiers: Rc<RefCell<BTreeSet<Address>>>,
    has_masp_tx: bool,
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
            has_masp_tx: false,
            _marker: PhantomData,
        }
    }

    /// Insert a verifier address whose VP will verify the tx.
    pub(crate) fn insert_verifier(&mut self, addr: &Address) {
        self.verifiers.borrow_mut().insert(addr.clone());
    }

    /// Set to enable a shielded transfer
    pub fn enable_shielded_transfer(&mut self) {
        self.has_masp_tx = true;
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

    /// Get the token address and the amount from PrefixedCoin. If the base
    /// denom is not an address, it returns `IbcToken`
    fn get_token_amount(
        &self,
        coin: &PrefixedCoin,
    ) -> Result<(Address, Amount), HostError> {
        let token = match Address::decode(coin.denom.base_denom.as_str()) {
            Ok(token_addr) if coin.denom.trace_path.is_empty() => token_addr,
            _ => trace::ibc_token(coin.denom.to_string()),
        };

        // Convert IBC amount to Namada amount for the token
        let uint_amount = Uint(primitive_types::U256::from(coin.amount).0);
        let amount = Amount::from_uint(uint_amount, 0).map_err(|e| {
            HostError::Other {
                description: format!(
                    "The IBC amount is invalid: Coin {coin}, Error {e}",
                ),
            }
        })?;

        Ok((token, amount))
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
    fn add_deposit(
        &self,
        token: &Address,
        amount: Amount,
    ) -> Result<(), HostError> {
        let deposit = self.inner.borrow().deposit(token)?;
        let added_deposit =
            deposit
                .checked_add(amount)
                .ok_or_else(|| HostError::Other {
                    description: "The per-epoch deposit overflowed".to_string(),
                })?;
        self.inner.borrow_mut().store_deposit(token, added_deposit)
    }

    /// Add the amount to the per-epoch withdraw of the token
    fn add_withdraw(
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

    #[allow(dead_code)]
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
        if amount.is_zero() {
            return Ok(());
        }

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
            use namada_state::StorageRead;

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
                .storage()
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

        // TODO: emit masp events

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
    type AccountId = Address;

    fn sender_account(
        &self,
        signer: &Signer,
    ) -> Result<Self::AccountId, HostError> {
        Address::decode(signer.as_ref()).map_err(|e| HostError::Other {
            description: format!(
                "Decoding the signer failed: {signer}, error {e}"
            ),
        })
    }

    fn receiver_account(
        &self,
        signer: &Signer,
    ) -> Result<Self::AccountId, HostError> {
        Address::try_from(signer).map_err(|e| HostError::Other {
            description: format!(
                "Decoding the signer failed: {signer}, error {e}"
            ),
        })
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
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.add_withdraw(&ibc_token, amount)?;

        // A transfer of NUT tokens must be verified by their VP
        if ibc_token.is_internal()
            && matches!(ibc_token, Address::Internal(InternalAddress::Nut(_)))
        {
            self.insert_verifier(&ibc_token);
        }

        let from_account = if self.has_masp_tx {
            &MASP
        } else {
            from_account
        };

        self.inner
            .borrow_mut()
            .transfer_token(
                from_account,
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
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.add_deposit(&ibc_token, amount)?;

        self.inner
            .borrow_mut()
            .transfer_token(&IBC_ESCROW_ADDRESS, to_account, &ibc_token, amount)
            .map_err(HostError::from)
    }

    fn mint_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), HostError> {
        // The trace path of the denom is already updated if receiving the token
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.update_mint_amount(&ibc_token, amount, true)?;
        self.add_deposit(&ibc_token, amount)?;

        // A transfer of NUT tokens must be verified by their VP
        if ibc_token.is_internal()
            && matches!(ibc_token, Address::Internal(InternalAddress::Nut(_)))
        {
            self.insert_verifier(&ibc_token);
        }

        // Store the IBC denom with the token hash to be able to retrieve it
        // later
        self.maybe_store_ibc_denom(account, coin)?;

        self.inner
            .borrow_mut()
            .mint_token(account, &ibc_token, amount)
            .map_err(HostError::from)
    }

    fn burn_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), HostError> {
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.update_mint_amount(&ibc_token, amount, false)?;
        self.add_withdraw(&ibc_token, amount)?;

        // A transfer of NUT tokens must be verified by their VP
        if ibc_token.is_internal()
            && matches!(ibc_token, Address::Internal(InternalAddress::Nut(_)))
        {
            self.insert_verifier(&ibc_token);
        }

        let account = if self.has_masp_tx { &MASP } else { account };

        // The burn is "unminting" from the minted balance
        self.inner
            .borrow_mut()
            .burn_token(account, &ibc_token, amount)
            .map_err(HostError::from)
    }
}
