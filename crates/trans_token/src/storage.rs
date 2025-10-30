use namada_core::address::{Address, InternalAddress};
use namada_core::hints;
pub use namada_core::storage::Key;
use namada_core::token::{self, Amount, AmountError, DenominatedAmount};

use crate::storage_key::*;
use crate::{Error, Result, ResultExt, StorageRead, StorageWrite};

/// Initialize parameters for the token in storage during the genesis block.
pub fn write_params<S>(storage: &mut S, address: &Address) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    storage.write(&minted_balance_key(address), Amount::zero())?;
    Ok(())
}

/// Read the balance of a given token and owner.
pub fn read_balance<S>(
    storage: &S,
    token: &Address,
    owner: &Address,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    let key = balance_key(token, owner);
    let balance = storage.read::<token::Amount>(&key)?.unwrap_or_default();
    Ok(balance)
}

/// Update the balance of a given token and owner.
pub fn update_balance<S, F>(
    storage: &mut S,
    token: &Address,
    owner: &Address,
    f: F,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
    F: FnOnce(token::Amount) -> Result<token::Amount>,
{
    let key = balance_key(token, owner);
    let balance = storage.read::<token::Amount>(&key)?.unwrap_or_default();
    let new_balance = f(balance)?;
    storage.write(&key, new_balance)
}

/// Increment the balance of a given token and owner.
pub fn increment_balance<S>(
    storage: &mut S,
    token: &Address,
    owner: &Address,
    amount: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    update_balance(storage, token, owner, |cur_amount| {
        cur_amount
            .checked_add(amount)
            .ok_or(AmountError::Overflow)
            .into_storage_result()
    })
}

/// Decrement the balance of a given token and owner.
pub fn decrement_balance<S>(
    storage: &mut S,
    token: &Address,
    owner: &Address,
    amount: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    update_balance(storage, token, owner, |cur_amount| {
        cur_amount
            .checked_sub(amount)
            .ok_or(AmountError::Insufficient)
            .into_storage_result()
    })
}

/// Read the total network supply of a given token.
pub fn read_total_supply<S>(
    storage: &S,
    token: &Address,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    let key = minted_balance_key(token);
    let total_supply = storage.read::<token::Amount>(&key)?.unwrap_or_default();
    Ok(total_supply)
}

/// Update the total network supply of a given token.
pub fn update_total_supply<S, F>(
    storage: &mut S,
    token: &Address,
    f: F,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
    F: FnOnce(token::Amount) -> Result<token::Amount>,
{
    let key = minted_balance_key(token);
    let total_supply = storage.read::<token::Amount>(&key)?.unwrap_or_default();
    let new_supply = f(total_supply)?;
    storage.write(&key, new_supply)
}

/// Increment the total network supply of a given token.
pub fn increment_total_supply<S>(
    storage: &mut S,
    token: &Address,
    amount: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    update_total_supply(storage, token, |cur_supply| {
        cur_supply
            .checked_add(amount)
            .ok_or(AmountError::Overflow)
            .into_storage_result()
    })
}

/// Decrement the total network supply of a given token.
pub fn decrement_total_supply<S>(
    storage: &mut S,
    token: &Address,
    amount: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    update_total_supply(storage, token, |cur_supply| {
        cur_supply
            .checked_sub(amount)
            .ok_or(AmountError::Insufficient)
            .into_storage_result()
    })
}

/// Get the effective circulating total supply of native tokens.
pub fn get_effective_total_native_supply<S>(
    storage: &S,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    let native_token = storage.get_native_token()?;
    let pgf_address = Address::Internal(InternalAddress::Pgf);

    let raw_total = read_total_supply(storage, &native_token)?;
    let pgf_balance = read_balance(storage, &native_token, &pgf_address)?;

    // Remove native balance in PGF address from the total supply
    Ok(raw_total
        .checked_sub(pgf_balance)
        .expect("Raw total supply should be larger than PGF balance"))
}

/// Read the denomination of a given token, if any. Note that native
/// transparent tokens do not have this set and instead use the constant
/// [`token::NATIVE_MAX_DECIMAL_PLACES`].
pub fn read_denom<S>(
    storage: &S,
    token: &Address,
) -> Result<Option<token::Denomination>>
where
    S: StorageRead,
{
    let (key, is_default_zero) = match token {
        Address::Internal(InternalAddress::IbcToken(_)) => {
            return Ok(Some(0u8.into()));
        }
        token => (denom_key(token), false),
    };
    storage.read(&key).map(|opt_denom| {
        Some(opt_denom.unwrap_or_else(|| {
            if is_default_zero {
                0u8.into()
            } else {
                // FIXME: perhaps when we take this branch, we should
                // assume the same behavior as NUTs? maybe this branch
                // is unreachable, anyway. when would regular tokens
                // ever not be denominated?
                hints::cold();
                token::NATIVE_MAX_DECIMAL_PLACES.into()
            }
        }))
    })
}

/// Write the denomination of a given token.
pub fn write_denom<S>(
    storage: &mut S,
    token: &Address,
    denom: token::Denomination,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = denom_key(token);
    storage.write(&key, denom)
}

/// Apply transfer of a `token` from `src` to `dest` in storage.
///
/// Returns an `Err` if `src` has insufficient balance or if the transfer the
/// `dest` would overflow (This can only happen if the total supply doesn't fit
/// in `token::Amount`).
///
/// For a regular token transfer in a transaction, use
/// [tx::transfer](crate::tx::transfer) instead that inserts a verifier expected
/// by the token VP and emits a transfer events.
pub fn transfer<S>(
    storage: &mut S,
    token: &Address,
    src: &Address,
    dest: &Address,
    amount: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    if amount.is_zero() || src == dest {
        return Ok(());
    }

    let src_key = balance_key(token, src);
    let src_balance = read_balance(storage, token, src)?;
    match src_balance.checked_sub(amount) {
        Some(new_src_balance) => {
            let dest_key = balance_key(token, dest);
            let dest_balance = read_balance(storage, token, dest)?;
            match dest_balance.checked_add(amount) {
                Some(new_dest_balance) => {
                    storage.write(&src_key, new_src_balance)?;
                    storage.write(&dest_key, new_dest_balance)
                }
                None => Err(Error::new_alloc(format!(
                    "The transfer would overflow balance of {dest}"
                ))),
            }
        }
        None => {
            Err(Error::new_alloc(format!("{src} has insufficient balance")))
        }
    }
}

/// Mint `amount` of `token` as `minter` to `dest`.
pub fn mint_tokens<S>(
    storage: &mut S,
    minter: &Address,
    token: &Address,
    dest: &Address,
    amount: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    credit_tokens(storage, token, dest, amount)?;
    storage.write(&minter_key(token), minter)
}

/// Credit tokens to an account, to be used only by protocol. In transactions,
/// this would get rejected by the default `vp_token`.
pub fn credit_tokens<S>(
    storage: &mut S,
    token: &Address,
    dest: &Address,
    amount: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    // Increment the destination balance
    increment_balance(storage, token, dest, amount)?;

    // Increment the total supply
    increment_total_supply(storage, token, amount)
}

/// Burn a specified amount of tokens from some address.
///
/// If the burn amount is larger than the total balance of the given address,
/// then the remaining balance is burned. The total supply of the token is
/// properly adjusted.
pub fn burn_tokens<S>(
    storage: &mut S,
    token: &Address,
    source: &Address,
    amount: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let source_balance_key = balance_key(token, source);
    let source_balance = read_balance(storage, token, source)?;

    let amount_to_burn =
        if let Some(new_amount) = source_balance.checked_sub(amount) {
            storage.write(&source_balance_key, new_amount)?;
            amount
        } else {
            storage.write(&source_balance_key, token::Amount::zero())?;
            source_balance
        };

    // Decrement the total supply
    decrement_total_supply(storage, token, amount_to_burn)
}

/// Add denomination info if it exists in storage.
pub fn denominated(
    amount: token::Amount,
    token: &Address,
    storage: &impl StorageRead,
) -> Result<DenominatedAmount> {
    let denom = read_denom(storage, token)?.ok_or_else(|| {
        Error::SimpleMessage(
            "No denomination found in storage for the given token",
        )
    })?;
    Ok(DenominatedAmount::new(amount, denom))
}

/// Convert this denominated amount into a plain amount by increasing its
/// precision to the given token's denomination and then taking the
/// significand.
pub fn denom_to_amount(
    denom_amount: DenominatedAmount,
    token: &Address,
    storage: &impl StorageRead,
) -> Result<Amount> {
    #[cfg(not(fuzzing))]
    {
        let denom = read_denom(storage, token)?.ok_or_else(|| {
            Error::SimpleMessage(
                "No denomination found in storage for the given token",
            )
        })?;
        denom_amount.scale(denom).map_err(Error::new)
    }

    #[cfg(fuzzing)]
    {
        let _ = (token, storage);
        Ok(denom_amount.amount())
    }
}

#[cfg(test)]
mod testing {
    use namada_core::{address, token};
    use namada_state::testing::TestStorage;

    use super::{
        burn_tokens, credit_tokens, read_balance, read_total_supply, transfer,
    };

    #[test]
    fn test_credit() {
        let mut storage = TestStorage::default();
        let native_token = address::testing::nam();

        // Get one account
        let addr = address::testing::gen_implicit_address();

        // Credit the account some balance
        let pre_balance = token::Amount::native_whole(1);
        credit_tokens(&mut storage, &native_token, &addr, pre_balance).unwrap();

        let total_supply_post =
            read_total_supply(&storage, &native_token).unwrap();

        assert_eq!(total_supply_post, pre_balance);

        let post_balance =
            read_balance(&storage, &native_token, &addr).unwrap();

        assert_eq!(post_balance, pre_balance);
    }

    #[test]
    fn test_transfer_to_self_is_no_op() {
        let mut storage = TestStorage::default();
        let native_token = address::testing::nam();

        // Get one account
        let addr = address::testing::gen_implicit_address();

        // Credit the account some balance
        let pre_balance = token::Amount::native_whole(1);
        credit_tokens(&mut storage, &native_token, &addr, pre_balance).unwrap();

        let total_supply_pre =
            read_total_supply(&storage, &native_token).unwrap();

        let transfer_result =
            transfer(&mut storage, &native_token, &addr, &addr, pre_balance);
        assert!(transfer_result.is_ok());

        let total_supply_post =
            read_total_supply(&storage, &native_token).unwrap();

        assert_eq!(total_supply_post, total_supply_pre);

        let post_balance =
            read_balance(&storage, &native_token, &addr).unwrap();

        assert_eq!(post_balance, pre_balance);
    }

    #[test]
    fn test_transfer() {
        let mut storage = TestStorage::default();
        let native_token = address::testing::nam();

        // Get one account
        let source = address::testing::gen_implicit_address();
        let target = address::testing::gen_implicit_address();

        // Credit the account some balance
        let pre_balance = token::Amount::native_whole(1);
        credit_tokens(&mut storage, &native_token, &source, pre_balance)
            .unwrap();

        let total_supply_pre =
            read_total_supply(&storage, &native_token).unwrap();

        transfer(&mut storage, &native_token, &source, &target, pre_balance)
            .unwrap();

        let total_supply_post =
            read_total_supply(&storage, &native_token).unwrap();

        assert_eq!(total_supply_post, total_supply_pre);

        let post_balance_target =
            read_balance(&storage, &native_token, &target).unwrap();
        let post_balance_source =
            read_balance(&storage, &native_token, &source).unwrap();

        assert_eq!(post_balance_target, pre_balance);
        assert_eq!(post_balance_source, token::Amount::native_whole(0));
    }

    #[test]
    fn test_burn_native_tokens() {
        let mut storage = TestStorage::default();
        let native_token = address::testing::nam();

        // Get some addresses
        let addr1 = address::testing::gen_implicit_address();
        let addr2 = address::testing::gen_implicit_address();
        let addr3 = address::testing::gen_implicit_address();

        let balance1 = token::Amount::native_whole(1);
        let balance2 = token::Amount::native_whole(2);
        let balance3 = token::Amount::native_whole(3);
        let tot_init_balance = balance1 + balance2 + balance3;

        credit_tokens(&mut storage, &native_token, &addr1, balance1).unwrap();
        credit_tokens(&mut storage, &native_token, &addr2, balance2).unwrap();
        credit_tokens(&mut storage, &native_token, &addr3, balance3).unwrap();

        // Check total initial supply
        let total_supply = read_total_supply(&storage, &native_token).unwrap();
        assert_eq!(total_supply, tot_init_balance);

        // Burn some tokens
        let burn1 = token::Amount::from(547_432);
        burn_tokens(&mut storage, &native_token, &addr1, burn1).unwrap();

        // Check new balances
        let addr1_balance =
            read_balance(&storage, &native_token, &addr1).unwrap();
        assert_eq!(addr1_balance, balance1 - burn1);
        let total_supply = read_total_supply(&storage, &native_token).unwrap();
        assert_eq!(total_supply, tot_init_balance - burn1);

        // Burn more tokens from addr1 than it has remaining
        let burn2 = token::Amount::from(1_000_000);
        burn_tokens(&mut storage, &native_token, &addr1, burn2).unwrap();

        // Check new balances
        let addr1_balance =
            read_balance(&storage, &native_token, &addr1).unwrap();
        assert_eq!(addr1_balance, token::Amount::zero());
        let total_supply = read_total_supply(&storage, &native_token).unwrap();
        assert_eq!(total_supply, tot_init_balance - balance1);

        // Burn more tokens from addr2 than are in the total supply
        let burn3 = tot_init_balance + token::Amount::native_whole(1);
        burn_tokens(&mut storage, &native_token, &addr2, burn3).unwrap();

        // Check balances again
        let addr2_balance =
            read_balance(&storage, &native_token, &addr2).unwrap();
        assert_eq!(addr2_balance, token::Amount::zero());
        let total_supply = read_total_supply(&storage, &native_token).unwrap();
        assert_eq!(total_supply, balance3);
    }
}
