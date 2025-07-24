//! Token transfers

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use namada_core::address::Address;
use namada_core::collections::HashSet;
use namada_events::{EmitEvents, EventLevel};
use namada_state::Error;
use namada_tx_env::{Result, TxEnv};

use crate::event::{TokenEvent, TokenOperation};
use crate::storage_key::balance_key;
use crate::{Amount, UserAccount, read_balance};

/// Multi-transfer credit or debit amounts
pub trait CreditOrDebit {
    /// Gets an iterator over the pair of credited or debited owners and token
    /// addresses, in sorted order.
    fn keys(&self) -> impl Iterator<Item = (Address, Address)>;

    /// Returns a reference to the value corresponding to pair of owner and
    /// token address
    fn get(&self, key: &(Address, Address)) -> Option<&Amount>;

    /// Gets an owning iterator over the pairs of credited or debited owners and
    /// token addresses paired with the token amount, sorted by key.
    fn into_iter(
        self,
    ) -> impl IntoIterator<Item = ((Address, Address), Amount)>;
}

impl CreditOrDebit for BTreeMap<(Address, Address), Amount> {
    fn keys(&self) -> impl Iterator<Item = (Address, Address)> {
        self.keys().cloned()
    }

    fn get(&self, key: &(Address, Address)) -> Option<&Amount> {
        self.get(key)
    }

    fn into_iter(
        self,
    ) -> impl IntoIterator<Item = ((Address, Address), Amount)> {
        IntoIterator::into_iter(self)
    }
}

/// Transfer tokens from `sources` to `dests`.
///
/// Returns an `Err` if any source has insufficient balance or if the transfer
/// to any destination would overflow (This can only happen if the total supply
/// doesn't fit in `token::Amount`). Returns a pair comprising the set of
/// debited accounts and the set of tokens debited and credited by the transfer.
pub fn multi_transfer<ENV>(
    env: &mut ENV,
    sources: impl CreditOrDebit,
    targets: impl CreditOrDebit,
    event_desc: Cow<'static, str>,
) -> Result<(HashSet<Address>, HashSet<Address>)>
where
    ENV: TxEnv + EmitEvents,
{
    let mut debited_accounts = HashSet::new();
    // Collect all the accounts whose balance has changed
    let mut accounts = BTreeSet::new();
    accounts.extend(sources.keys());
    accounts.extend(targets.keys());

    let unexpected_err = || {
        Error::new_const(
            "Computing difference between amounts should never overflow",
        )
    };
    // Apply the balance change for each account in turn
    let mut any_balance_changed = false;
    // To store all the tokens used in the transfer
    let mut tokens = HashSet::new();
    for account @ (owner, token) in &accounts {
        // Record the encountered tokens
        tokens.insert(token.clone());
        let overflow_err = || {
            Error::new_alloc(format!(
                "The transfer would overflow balance of {owner}"
            ))
        };
        let underflow_err =
            || Error::new_alloc(format!("{owner} has insufficient balance"));
        // Load account balances and deltas
        let owner_key = balance_key(token, owner);
        let owner_balance = read_balance(env, token, owner)?;
        let src_amt = sources.get(account).cloned().unwrap_or_default();
        let dest_amt = targets.get(account).cloned().unwrap_or_default();
        // Compute owner_balance + dest_amt - src_amt
        let new_owner_balance = if src_amt <= dest_amt {
            owner_balance
                .checked_add(
                    dest_amt.checked_sub(src_amt).ok_or_else(unexpected_err)?,
                )
                .ok_or_else(overflow_err)?
        } else {
            debited_accounts.insert(owner.to_owned());
            owner_balance
                .checked_sub(
                    src_amt.checked_sub(dest_amt).ok_or_else(unexpected_err)?,
                )
                .ok_or_else(underflow_err)?
        };
        // Write the new balance
        if new_owner_balance != owner_balance {
            any_balance_changed = true;
            env.write(&owner_key, new_owner_balance)?;
        }
    }

    if !any_balance_changed {
        return Ok((debited_accounts, tokens));
    }

    let mut evt_sources = BTreeMap::new();
    let mut evt_targets = BTreeMap::new();
    let mut post_balances = BTreeMap::new();

    for ((src, token), amount) in sources.into_iter() {
        // The tx must be authorized by the source address
        env.insert_verifier(&src)?;
        if token.is_internal() {
            // Established address tokens do not have VPs themselves, their
            // validation is handled by the `Multitoken` internal address,
            // but internal token addresses have to verify
            // the transfer
            env.insert_verifier(&token)?;
        }
        evt_sources.insert(
            (UserAccount::Internal(src.clone()), token.clone()),
            amount.into(),
        );
        post_balances.insert(
            (UserAccount::Internal(src.clone()), token.clone()),
            crate::read_balance(env, &token, &src)?.into(),
        );
    }

    for ((target, token), amount) in targets.into_iter() {
        // The tx must be authorized by the involved address
        env.insert_verifier(&target)?;
        if token.is_internal() {
            // Established address tokens do not have VPs themselves, their
            // validation is handled by the `Multitoken` internal address,
            // but internal token addresses have to verify
            // the transfer
            env.insert_verifier(&token)?;
        }
        evt_targets.insert(
            (UserAccount::Internal(target.clone()), token.clone()),
            amount.into(),
        );
        post_balances.insert(
            (UserAccount::Internal(target.clone()), token.clone()),
            crate::read_balance(env, &token, &target)?.into(),
        );
    }

    env.emit(TokenEvent {
        descriptor: event_desc,
        level: EventLevel::Tx,
        operation: TokenOperation::Transfer {
            sources: evt_sources,
            targets: evt_targets,
            post_balances,
        },
    });

    Ok((debited_accounts, tokens))
}

#[derive(Debug, Clone)]
struct SingleCreditOrDebit {
    src_or_dest: Address,
    token: Address,
    amount: Amount,
}

impl CreditOrDebit for SingleCreditOrDebit {
    fn keys(&self) -> impl Iterator<Item = (Address, Address)> {
        [(self.src_or_dest.clone(), self.token.clone())].into_iter()
    }

    fn get(
        &self,
        (key_owner, key_token): &(Address, Address),
    ) -> Option<&Amount> {
        if key_token == &self.token && key_owner == &self.src_or_dest {
            return Some(&self.amount);
        }
        None
    }

    fn into_iter(
        self,
    ) -> impl IntoIterator<Item = ((Address, Address), Amount)> {
        [((self.src_or_dest.clone(), self.token.clone()), self.amount)]
    }
}

/// Transfer transparent token, insert the verifier expected by the VP and an
/// emit an event.
pub fn transfer<ENV>(
    env: &mut ENV,
    source: &Address,
    target: &Address,
    token: &Address,
    amount: Amount,
    event_desc: Cow<'static, str>,
) -> Result<()>
where
    ENV: TxEnv + EmitEvents,
{
    multi_transfer(
        env,
        SingleCreditOrDebit {
            src_or_dest: source.clone(),
            token: token.clone(),
            amount,
        },
        SingleCreditOrDebit {
            src_or_dest: target.clone(),
            token: token.clone(),
            amount,
        },
        event_desc,
    )?;

    Ok(())
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use namada_core::address::testing::{
        arb_address, arb_non_internal_address,
    };
    use namada_core::token::testing::arb_amount;
    use namada_core::uint::Uint;
    use namada_core::{address, token};
    use namada_events::extend::{EventAttributeEntry, InnerTxHash, TxHash};
    use namada_tests::tx::{ctx, tx_host_env};
    use namada_tx::data::InnerTxId;
    use proptest::prelude::*;

    use super::*;
    use crate::event::{PostBalances, SourceAccounts, TargetAccounts};

    const EVENT_DESC: Cow<'static, str> = Cow::Borrowed("event-desc");

    proptest! {
        #[test]
        fn test_valid_transfer_tx(
            (src, dest, token) in (
                arb_non_internal_address(),
                arb_non_internal_address(),
                arb_address()
            ).prop_filter("unique addresses", |(src, dest, token)|
                src != dest && dest != token && src != token),

            amount in arb_amount(),
        ) {
            // Test via `fn transfer`
            test_valid_transfer_tx_aux(src.clone(), dest.clone(), token.clone(), amount, || {
                transfer(ctx(), &src, &dest, &token, amount, EVENT_DESC).unwrap();
            });

            // Clean-up tx env before running next test
            let _old_env = tx_host_env::take();

            // Test via `fn multi_transfer`
            test_valid_transfer_tx_aux(src.clone(), dest.clone(), token.clone(), amount, || {
                let sources =
                    BTreeMap::from_iter([((src.clone(), token.clone()), amount)]);

                let targets =
                    BTreeMap::from_iter([((dest.clone(), token.clone()), amount)]);

                let (debited_accounts, _token) =
                    multi_transfer(ctx(), sources, targets, EVENT_DESC).unwrap();

                if amount.is_zero() {
                    assert!(debited_accounts.is_empty());
                } else {
                    assert_eq!(debited_accounts.len(), 1);
                    assert!(debited_accounts.contains(&src));
                }
            });
        }
    }

    fn test_valid_transfer_tx_aux<F: FnOnce()>(
        src: Address,
        dest: Address,
        token: Address,
        amount: Amount,
        apply_transfer: F,
    ) {
        tx_host_env::init();

        tx_host_env::with(|tx_env| {
            tx_env.spawn_accounts([&src, &dest, &token]);
            tx_env.credit_tokens(&src, &token, amount);
        });
        assert_eq!(read_balance(ctx(), &token, &src).unwrap(), amount);

        apply_transfer();

        // Dest received the amount
        assert_eq!(read_balance(ctx(), &token, &dest).unwrap(), amount);

        // Src spent the amount
        assert_eq!(
            read_balance(ctx(), &token, &src).unwrap(),
            token::Amount::zero()
        );

        tx_host_env::with(|tx_env| {
            // Internal token address have to be part of the verifier set
            assert!(!token.is_internal() || tx_env.verifiers.contains(&token));
            // Src and dest should always verify
            assert!(tx_env.verifiers.contains(&src));
            assert!(tx_env.verifiers.contains(&dest));
        });

        // The transfer must emit an event
        tx_host_env::with(|tx_env| {
            let events: Vec<_> = tx_env
                .state
                .write_log()
                .get_events_of::<TokenEvent>()
                .collect();
            assert_eq!(events.len(), 1);
            let event = events[0].clone();
            assert_eq!(event.level(), &EventLevel::Tx);
            assert_eq!(event.kind(), &crate::event::types::TRANSFER);
            let attrs = event.into_attributes();
            let amount_uint: Uint = amount.into();

            let inner_tx_id = InnerTxId {
                wrapper_hash: None,
                commitments_hash: Cow::Owned(tx_env.batched_tx.cmt.get_hash()),
            };
            let exp_tx_hash = inner_tx_id.wrapper_hash().to_string();
            let exp_inner_tx_hash = inner_tx_id.inner_hash().to_string();
            let exp_balances = if src < dest {
                format!(
                    "[[[\"internal-address/{src}\",\"{token}\"],\"0\"],[[\"\
                     internal-address/{dest}\",\"{token}\"],\"{amount_uint}\"\
                     ]]",
                )
            } else {
                format!(
                    "[[[\"internal-address/{dest}\",\"{token}\"],\"\
                     {amount_uint}\"],[[\"internal-address/{src}\",\"{token}\"\
                     ],\"0\"]]",
                )
            };
            let exp_sources = format!(
                "[[[\"internal-address/{src}\",\"{token}\"],\"{amount_uint}\"\
                 ]]",
            );
            let exp_targets = format!(
                "[[[\"internal-address/{dest}\",\"{token}\"],\"{amount_uint}\"\
                 ]]",
            );

            itertools::assert_equal(
                attrs,
                BTreeMap::from_iter([
                    (TxHash::KEY.to_string(), exp_tx_hash),
                    (InnerTxHash::KEY.to_string(), exp_inner_tx_hash),
                    (PostBalances::KEY.to_string(), exp_balances),
                    (SourceAccounts::KEY.to_string(), exp_sources),
                    (TargetAccounts::KEY.to_string(), exp_targets),
                    (
                        "token-event-descriptor".to_string(),
                        EVENT_DESC.to_string(),
                    ),
                ]),
            );
        })
    }

    #[test]
    fn test_transfer_tx_zero_amount_is_noop() {
        let src = address::testing::established_address_1();
        let dest = address::testing::established_address_2();
        let token = address::testing::established_address_3();
        let amount = token::Amount::zero();
        let src_balance = token::Amount::native_whole(1);
        let dest_balance = token::Amount::native_whole(1);

        tx_host_env::init();

        tx_host_env::with(|tx_env| {
            tx_env.spawn_accounts([&src, &dest, &token]);
            tx_env.credit_tokens(&src, &token, src_balance);
            tx_env.credit_tokens(&dest, &token, src_balance);
        });

        transfer(ctx(), &src, &dest, &token, amount, EVENT_DESC).unwrap();

        // Dest balance is still the same
        assert_eq!(read_balance(ctx(), &token, &dest).unwrap(), dest_balance);

        // Src balance is still the same
        assert_eq!(read_balance(ctx(), &token, &src).unwrap(), src_balance);

        // Verifiers set is empty
        tx_host_env::with(|tx_env| {
            assert!(tx_env.verifiers.is_empty());
        });

        // Must no emit an event
        tx_host_env::with(|tx_env| {
            let events: Vec<_> = tx_env
                .state
                .write_log()
                .get_events_of::<TokenEvent>()
                .collect();
            assert!(events.is_empty());
        });
    }

    #[test]
    fn test_transfer_tx_to_self_is_noop() {
        let src = address::testing::established_address_1();
        let token = address::testing::established_address_2();
        let amount = token::Amount::zero();
        let src_balance = token::Amount::native_whole(1);

        tx_host_env::init();

        tx_host_env::with(|tx_env| {
            tx_env.spawn_accounts([&src, &token]);
            tx_env.credit_tokens(&src, &token, src_balance);
        });

        transfer(ctx(), &src, &src, &token, amount, EVENT_DESC).unwrap();

        // Src balance is still the same
        assert_eq!(read_balance(ctx(), &token, &src).unwrap(), src_balance);

        // Verifiers set is empty
        tx_host_env::with(|tx_env| {
            assert!(tx_env.verifiers.is_empty());
        });

        // Must no emit an event
        tx_host_env::with(|tx_env| {
            let events: Vec<_> = tx_env
                .state
                .write_log()
                .get_events_of::<TokenEvent>()
                .collect();
            assert!(events.is_empty());
        });
    }

    #[test]
    fn test_transfer_tx_to_self_with_insufficient_balance() {
        let src = address::testing::established_address_1();
        let token = address::testing::established_address_2();
        let amount = token::Amount::native_whole(10);
        let src_balance = token::Amount::native_whole(1);
        assert!(amount > src_balance);

        tx_host_env::init();

        tx_host_env::with(|tx_env| {
            tx_env.spawn_accounts([&src, &token]);
            tx_env.credit_tokens(&src, &token, src_balance);
        });

        transfer(ctx(), &src, &src, &token, amount, EVENT_DESC).unwrap();

        // Src balance is still the same
        assert_eq!(read_balance(ctx(), &token, &src).unwrap(), src_balance);

        // Verifiers set is empty
        tx_host_env::with(|tx_env| {
            assert!(tx_env.verifiers.is_empty());
        });

        // Must no emit an event
        tx_host_env::with(|tx_env| {
            let events: Vec<_> = tx_env
                .state
                .write_log()
                .get_events_of::<TokenEvent>()
                .collect();
            assert!(events.is_empty());
        });
    }

    /// Test a 3-way transfer between three participants:
    ///
    /// 1. (p1, token1, amount1) -> p2
    /// 2. (p2, token1, amount2) -> p3
    /// 3. (p3, token2, amount3) -> p1
    #[test]
    fn test_three_way_multi_transfer_tx() {
        tx_host_env::init();

        let p1 = address::testing::established_address_1();
        let p2 = address::testing::established_address_2();
        let p3 = address::testing::established_address_3();
        let token1 = address::testing::established_address_4();
        let token2 = address::testing::established_address_5();
        let amount1 = token::Amount::native_whole(10);
        let amount2 = token::Amount::native_whole(3);
        let amount3 = token::Amount::native_whole(90);

        tx_host_env::with(|tx_env| {
            tx_env.spawn_accounts([&p1, &p2, &p3, &token1, &token2]);
            tx_env.credit_tokens(&p1, &token1, amount1);
            tx_env.credit_tokens(&p3, &token2, amount3);
        });
        assert_eq!(read_balance(ctx(), &token1, &p1).unwrap(), amount1);
        assert_eq!(read_balance(ctx(), &token1, &p2).unwrap(), Amount::zero());
        assert_eq!(read_balance(ctx(), &token1, &p3).unwrap(), Amount::zero());
        assert_eq!(read_balance(ctx(), &token2, &p1).unwrap(), Amount::zero());
        assert_eq!(read_balance(ctx(), &token2, &p2).unwrap(), Amount::zero());
        assert_eq!(read_balance(ctx(), &token2, &p3).unwrap(), amount3);

        let sources = BTreeMap::from_iter([
            ((p1.clone(), token1.clone()), amount1),
            ((p2.clone(), token1.clone()), amount2),
            ((p3.clone(), token2.clone()), amount3),
        ]);

        let targets = BTreeMap::from_iter([
            ((p2.clone(), token1.clone()), amount1),
            ((p3.clone(), token1.clone()), amount2),
            ((p1.clone(), token2.clone()), amount3),
        ]);

        let (debited_accounts, _token) =
            multi_transfer(ctx(), sources, targets, EVENT_DESC).unwrap();

        // p2 is not debited as it received more of token1 than it spent
        assert_eq!(debited_accounts.len(), 2);
        assert!(debited_accounts.contains(&p1));
        assert!(debited_accounts.contains(&p3));

        // p1 spent all token1
        assert_eq!(read_balance(ctx(), &token1, &p1).unwrap(), Amount::zero());
        // p1 received token2
        assert_eq!(read_balance(ctx(), &token2, &p1).unwrap(), amount3);

        // p2 received amount1 and spent amount2 of token1
        assert_eq!(
            read_balance(ctx(), &token1, &p2).unwrap(),
            amount1 - amount2
        );
        // p2 doesn't have any token2
        assert_eq!(read_balance(ctx(), &token2, &p2).unwrap(), Amount::zero());

        // p3 received token1
        assert_eq!(read_balance(ctx(), &token1, &p3).unwrap(), amount2);
        // p3 spent token2
        assert_eq!(read_balance(ctx(), &token2, &p3).unwrap(), Amount::zero());

        tx_host_env::with(|tx_env| {
            // All parties should always verify
            assert!(tx_env.verifiers.contains(&p1));
            assert!(tx_env.verifiers.contains(&p2));
            assert!(tx_env.verifiers.contains(&p3));
        });

        // The transfer must emit an event
        tx_host_env::with(|tx_env| {
            let events: Vec<_> = tx_env
                .state
                .write_log()
                .get_events_of::<TokenEvent>()
                .collect();
            assert_eq!(events.len(), 1);
            let event = events[0].clone();
            assert_eq!(event.level(), &EventLevel::Tx);
            assert_eq!(event.kind(), &crate::event::types::TRANSFER);

            dbg!(event.into_attributes());
        })
    }

    #[test]
    fn test_multi_transfer_to_self_is_no_op() {
        tx_host_env::init();

        let token = address::testing::nam();

        // Get one account
        let addr = address::testing::gen_implicit_address();

        // Credit the account some balance
        let pre_balance = token::Amount::native_whole(1);
        tx_host_env::with(|tx_env| {
            tx_env.credit_tokens(&addr, &token, pre_balance);
        });

        let pre_balance_check = read_balance(ctx(), &token, &addr).unwrap();

        assert_eq!(pre_balance_check, pre_balance);

        let sources =
            BTreeMap::from_iter([((addr.clone(), token.clone()), pre_balance)]);

        let targets =
            BTreeMap::from_iter([((addr.clone(), token.clone()), pre_balance)]);

        let (debited_accounts, _token) =
            multi_transfer(ctx(), sources, targets, EVENT_DESC).unwrap();

        // No account has been debited
        assert!(debited_accounts.is_empty());

        // Balance is the same
        let post_balance_check = read_balance(ctx(), &token, &addr).unwrap();
        assert_eq!(post_balance_check, pre_balance);

        // Verifiers set is empty
        tx_host_env::with(|tx_env| {
            assert!(tx_env.verifiers.is_empty());
        });

        // Must no emit an event
        tx_host_env::with(|tx_env| {
            let events: Vec<_> = tx_env
                .state
                .write_log()
                .get_events_of::<TokenEvent>()
                .collect();
            assert!(events.is_empty());
        });
    }

    #[test]
    fn test_multi_transfer_tx_to_self_with_insufficient_balance() {
        let src = address::testing::established_address_1();
        let token = address::testing::established_address_2();
        let amount = token::Amount::native_whole(10);
        let src_balance = token::Amount::native_whole(1);
        assert!(amount > src_balance);

        tx_host_env::init();

        tx_host_env::with(|tx_env| {
            tx_env.spawn_accounts([&src, &token]);
            tx_env.credit_tokens(&src, &token, src_balance);
        });

        let sources =
            BTreeMap::from_iter([((src.clone(), token.clone()), amount)]);

        let targets =
            BTreeMap::from_iter([((src.clone(), token.clone()), amount)]);

        let (debited_accounts, _token) =
            multi_transfer(ctx(), sources, targets, EVENT_DESC).unwrap();

        // No account has been debited
        assert!(debited_accounts.is_empty());

        // Src balance is still the same
        assert_eq!(read_balance(ctx(), &token, &src).unwrap(), src_balance);

        // Verifiers set is empty
        tx_host_env::with(|tx_env| {
            assert!(tx_env.verifiers.is_empty());
        });

        // Must no emit an event
        tx_host_env::with(|tx_env| {
            let events: Vec<_> = tx_env
                .state
                .write_log()
                .get_events_of::<TokenEvent>()
                .collect();
            assert!(events.is_empty());
        });
    }
}
