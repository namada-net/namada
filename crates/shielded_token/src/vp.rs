//! MASP native VP

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use borsh::BorshDeserialize;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::transparent::Authorization;
use masp_primitives::transaction::components::{
    I128Sum, TxIn, TxOut, ValueSum,
};
use masp_primitives::transaction::{Transaction, TransparentAddress};
use namada_core::address::{self, Address};
use namada_core::arith::{CheckedAdd, CheckedSub, checked};
use namada_core::booleans::BoolResultUnitExt;
use namada_core::collections::HashSet;
use namada_core::masp::{MaspEpoch, TAddrData, addr_taddr, encode_asset_type};
use namada_core::storage::Key;
use namada_core::token;
use namada_core::token::{Amount, MaspDigitPos};
use namada_core::uint::I320;
use namada_state::{
    ConversionState, OptionExt, ReadConversionState, ResultExt,
};
use namada_systems::{governance, ibc, parameters, trans_token};
use namada_tx::BatchedTxRef;
use namada_vp_env::{Error, Result, VpEnv};

use crate::storage_key::{
    is_masp_key, is_masp_nullifier_key, is_masp_transfer_key,
    is_masp_undated_balance_key, masp_commitment_anchor_key,
    masp_commitment_tree_key, masp_convert_anchor_key, masp_nullifier_key,
    masp_undated_balance_key,
};
use crate::validation::verify_shielded_tx;

/// MASP VP
pub struct MaspVp<'ctx, CTX, Params, Gov, Ibc, TransToken, Transfer> {
    /// Generic types for DI
    pub _marker:
        PhantomData<(&'ctx CTX, Params, Gov, Ibc, TransToken, Transfer)>,
}

// Balances changed by a transaction
#[derive(Debug, Clone)]
struct ChangedBalances {
    // Maps undated asset types to their decodings
    undated_tokens:
        BTreeMap<AssetType, (Address, token::Denomination, MaspDigitPos)>,
    // Map between MASP transparent address and Namada types
    decoder: BTreeMap<TransparentAddress, TAddrData>,
    // Balances before the tx
    pre: BTreeMap<TransparentAddress, ValueSum<Address, Amount>>,
    // Balances after the tx
    post: BTreeMap<TransparentAddress, ValueSum<Address, Amount>>,
    // Undated MASP balances before the tx
    undated_pre: ValueSum<Address, Amount>,
    // Undated MASP balances after the tx
    undated_post: ValueSum<Address, Amount>,
}

// Default is manually implemented due to imperfect derive
impl Default for ChangedBalances {
    fn default() -> Self {
        Self {
            undated_tokens: Default::default(),
            decoder: Default::default(),
            pre: Default::default(),
            post: Default::default(),
            undated_pre: ValueSum::zero(),
            undated_post: ValueSum::zero(),
        }
    }
}

impl<'ctx, CTX, Params, Gov, Ibc, TransToken, Transfer>
    MaspVp<'ctx, CTX, Params, Gov, Ibc, TransToken, Transfer>
where
    CTX: VpEnv<'ctx>
        + namada_tx::action::Read<Err = Error>
        + ReadConversionState,
    Params: parameters::Read<<CTX as VpEnv<'ctx>>::Pre>,
    Gov: governance::Read<<CTX as VpEnv<'ctx>>::Pre>,
    Ibc: ibc::Read<<CTX as VpEnv<'ctx>>::Post>,
    TransToken:
        trans_token::Keys + trans_token::Read<<CTX as VpEnv<'ctx>>::Pre>,
    Transfer: BorshDeserialize,
{
    /// Run the validity predicate
    pub fn validate_tx(
        ctx: &'ctx CTX,
        tx_data: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        // Allow any changes to be done by a governance proposal
        if Gov::is_proposal_accepted(
            &ctx.pre(),
            tx_data.tx.data(tx_data.cmt).unwrap_or_default().as_ref(),
        )? {
            return Ok(());
        }

        let masp_keys_changed: Vec<&Key> =
            keys_changed.iter().filter(|key| is_masp_key(key)).collect();
        let masp_transfer_changes = masp_keys_changed
            .iter()
            .all(|key| is_masp_transfer_key(key));

        if masp_keys_changed.is_empty() {
            // Changing no MASP keys at all is fine
            Ok(())
        } else if masp_transfer_changes {
            // The MASP transfer keys can only be changed by a valid Transaction
            Self::is_valid_masp_transfer(ctx, tx_data, keys_changed, verifiers)
        } else {
            return Err(Error::new_const(
                "A governance proposal is required to modify MASP \
                 non-transfer keys",
            ));
        }
    }

    // Check that the transaction correctly revealed the nullifiers, if needed
    fn valid_nullifiers_reveal(
        ctx: &'ctx CTX,
        keys_changed: &BTreeSet<Key>,
        transaction: &Transaction,
    ) -> Result<()> {
        // Support set to check that a nullifier was not revealed more
        // than once in the same tx
        let mut revealed_nullifiers = HashSet::new();

        for description in transaction
            .sapling_bundle()
            .map_or(&vec![], |bundle| &bundle.shielded_spends)
        {
            let nullifier_key = masp_nullifier_key(&description.nullifier);
            if ctx.has_key_pre(&nullifier_key)?
                || revealed_nullifiers.contains(&nullifier_key)
            {
                let error = Error::new_alloc(format!(
                    "MASP double spending attempt, the nullifier {:?} has \
                     already been revealed previously",
                    description.nullifier.0,
                ));
                tracing::debug!("{error}");
                return Err(error);
            }

            // Check that the nullifier is indeed committed (no temp write
            // and no delete) and carries no associated data (the latter not
            // strictly necessary for validation, but we don't expect any
            // value for this key anyway)
            ctx.read_bytes_post(&nullifier_key)?
                .is_some_and(|value| value.is_empty())
                .ok_or_else(|| {
                    Error::new_const(
                        "The nullifier should have been committed with no \
                         associated data",
                    )
                })?;

            revealed_nullifiers.insert(nullifier_key);
        }

        // Check that no unneeded nullifier has been revealed
        for nullifier_key in
            keys_changed.iter().filter(|key| is_masp_nullifier_key(key))
        {
            if !revealed_nullifiers.contains(nullifier_key) {
                let error = Error::new_alloc(format!(
                    "An unexpected MASP nullifier key {nullifier_key} has \
                     been revealed by the transaction"
                ));
                tracing::debug!("{error}");
                return Err(error);
            }
        }

        Ok(())
    }

    // Store the undated balances before and after this tx is applied.
    fn apply_undated_balances(
        ctx: &'ctx CTX,
        keys_changed: &BTreeSet<Key>,
        mut result: ChangedBalances,
    ) -> Result<ChangedBalances> {
        // Record the undated balances of the keys that changed
        for token in keys_changed.iter().filter_map(is_masp_undated_balance_key)
        {
            // Read and store the undated balance before this tx is applied
            let pre_undated_balance: Amount = ctx
                .read_pre(&masp_undated_balance_key(&token))?
                .unwrap_or_default();
            // Attach the token type to the undated balance
            let pre_undated_balance =
                ValueSum::from_pair(token.clone(), pre_undated_balance);
            // Now finally record the undated balance
            result.undated_pre =
                checked!(result.undated_pre.clone() + &pre_undated_balance)
                    .map_err(Error::new)?;
            // Read and store the undated balance after this tx is applied
            let post_undated_balance: Amount = ctx
                .read_post(&masp_undated_balance_key(&token))?
                .unwrap_or_default();
            // Attach the token type to the undated balance
            let post_undated_balance =
                ValueSum::from_pair(token, post_undated_balance);
            // Now finally record the undated balance
            result.undated_post =
                checked!(result.undated_post.clone() + &post_undated_balance)
                    .map_err(Error::new)?;
        }
        Ok(result)
    }

    // Check that a transaction carrying output descriptions correctly updates
    // the tree and anchor in storage
    fn valid_note_commitment_update(
        ctx: &'ctx CTX,
        transaction: &Transaction,
    ) -> Result<()> {
        // Check that the merkle tree in storage has been correctly updated with
        // the output descriptions cmu
        let tree_key = masp_commitment_tree_key();
        let mut previous_tree: CommitmentTree<Node> = ctx
            .read_pre(&tree_key)?
            .ok_or(Error::new_const("Cannot read storage"))?;
        let post_tree: CommitmentTree<Node> = ctx
            .read_post(&tree_key)?
            .ok_or(Error::new_const("Cannot read storage"))?;

        // Based on the output descriptions of the transaction, update the
        // previous tree in storage
        for description in transaction
            .sapling_bundle()
            .map_or(&vec![], |bundle| &bundle.shielded_outputs)
        {
            previous_tree
                .append(Node::from_scalar(description.cmu))
                .map_err(|()| {
                    Error::new_const("Failed to update the commitment tree")
                })?;
        }
        // Check that the updated previous tree matches the actual post tree.
        // This verifies that all and only the necessary notes have been
        // appended to the tree
        if previous_tree != post_tree {
            let error = Error::new_const(
                "The note commitment tree was incorrectly updated",
            );
            tracing::debug!("{error}");
            return Err(error);
        }

        Ok(())
    }

    // Check that the spend descriptions anchors of a transaction are valid
    fn valid_spend_descriptions_anchor(
        ctx: &'ctx CTX,
        transaction: &Transaction,
    ) -> Result<()> {
        for description in transaction
            .sapling_bundle()
            .map_or(&vec![], |bundle| &bundle.shielded_spends)
        {
            let anchor_key = masp_commitment_anchor_key(description.anchor);

            // Check if the provided anchor was published before
            if !ctx.has_key_pre(&anchor_key)? {
                let error = Error::new_const(
                    "Spend description refers to an invalid anchor",
                );
                tracing::debug!("{error}");
                return Err(error);
            }
        }

        Ok(())
    }

    // Check that the convert descriptions anchors of a transaction are valid
    fn valid_convert_descriptions_anchor(
        ctx: &'ctx CTX,
        transaction: &Transaction,
    ) -> Result<()> {
        if let Some(bundle) = transaction.sapling_bundle() {
            if !bundle.shielded_converts.is_empty() {
                let anchor_key = masp_convert_anchor_key();
                let expected_anchor = ctx
                    .read_pre::<namada_core::hash::Hash>(&anchor_key)?
                    .ok_or(Error::new_const("Cannot read storage"))?;

                for description in &bundle.shielded_converts {
                    // Check if the provided anchor matches the current
                    // conversion tree's one
                    if namada_core::hash::Hash(description.anchor.to_bytes())
                        != expected_anchor
                    {
                        let error = Error::new_const(
                            "Convert description refers to an invalid anchor",
                        );
                        tracing::debug!("{error}");
                        return Err(error);
                    }
                }
            }
        }

        Ok(())
    }

    // Apply the balance change to the changed balances structure
    fn apply_balance_change(
        ctx: &'ctx CTX,
        mut result: ChangedBalances,
        [token, counterpart]: [&Address; 2],
    ) -> Result<ChangedBalances> {
        let denom = TransToken::read_denom(&ctx.pre(), token)?.ok_or_err_msg(
            "No denomination found in storage for the given token",
        )?;
        // Record the token without an epoch to facilitate later decoding
        undated_tokens(token, denom, &mut result.undated_tokens)?;
        let counterpart_balance_key =
            TransToken::balance_key(token, counterpart);
        let pre_balance: Amount =
            ctx.read_pre(&counterpart_balance_key)?.unwrap_or_default();
        let post_balance: Amount =
            ctx.read_post(&counterpart_balance_key)?.unwrap_or_default();
        // Public keys must be the hash of the sources/targets
        let addr_hash = addr_taddr(counterpart.clone());
        // Enable the decoding of these counterpart addresses
        result
            .decoder
            .insert(addr_hash, TAddrData::Addr(counterpart.clone()));
        let zero = ValueSum::zero();
        // Finally record the actual balance change starting with the initial
        // state
        let pre_entry = result.pre.get(&addr_hash).unwrap_or(&zero).clone();
        result.pre.insert(
            addr_hash,
            checked!(
                pre_entry + &ValueSum::from_pair((*token).clone(), pre_balance)
            )
            .map_err(Error::new)?,
        );
        // And then record the final state
        let post_entry = result.post.get(&addr_hash).cloned().unwrap_or(zero);
        result.post.insert(
            addr_hash,
            checked!(
                post_entry
                    + &ValueSum::from_pair((*token).clone(), post_balance)
            )
            .map_err(Error::new)?,
        );
        Result::<_>::Ok(result)
    }

    // Check that transfer is pinned correctly and record the balance changes
    fn validate_state_and_get_transfer_data(
        ctx: &'ctx CTX,
        keys_changed: &BTreeSet<Key>,
        tx_data: &[u8],
    ) -> Result<ChangedBalances> {
        // Get the changed balance keys
        let mut counterparts_balances = keys_changed
            .iter()
            .filter_map(TransToken::is_any_token_balance_key);

        // Apply the balance changes to the changed balances structure
        let changed_balances = counterparts_balances
            .try_fold(ChangedBalances::default(), |acc, account| {
                Self::apply_balance_change(ctx, acc, account)
            })?;

        // Apply the undated balances to the changed balances structure
        let mut changed_balances =
            Self::apply_undated_balances(ctx, keys_changed, changed_balances)?;

        let ibc_addr = TAddrData::Addr(address::IBC);
        // Enable decoding the IBC address hash
        changed_balances
            .decoder
            .insert(addr_taddr(address::IBC), ibc_addr);

        // Note the balance changes they imply
        let ChangedBalances {
            undated_tokens,
            decoder,
            pre,
            post,
            undated_pre,
            undated_post,
        } = changed_balances;
        let ibc::ChangedBalances { decoder, pre, post } =
            Ibc::apply_ibc_packet::<Transfer>(
                &ctx.post(),
                tx_data,
                ibc::ChangedBalances { decoder, pre, post },
                keys_changed,
            )?;
        Ok(ChangedBalances {
            undated_tokens,
            decoder,
            pre,
            post,
            undated_pre,
            undated_post,
        })
    }

    // Check that MASP Transaction and state changes are valid
    fn is_valid_masp_transfer(
        ctx: &'ctx CTX,
        batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        let masp_epoch_multiplier = Params::masp_epoch_multiplier(&ctx.pre())?;
        let masp_epoch = MaspEpoch::try_from_epoch(
            ctx.get_block_epoch()?,
            masp_epoch_multiplier,
        )
        .map_err(Error::new_const)?;
        let conversion_state = ctx.conversion_state();
        let tx_data = batched_tx
            .tx
            .data(batched_tx.cmt)
            .ok_or_err_msg("No transaction data")?;
        let actions = ctx.read_actions()?;
        // Try to get the Transaction object from the tx first (IBC) and from
        // the actions afterwards
        let shielded_tx = if let Some(tx) =
            Ibc::try_extract_masp_tx_from_envelope::<Transfer>(&tx_data)?
        {
            tx
        } else {
            let masp_section_ref =
                namada_tx::action::get_masp_section_ref(&actions)
                    .map_err(Error::new_const)?
                    .ok_or_else(|| {
                        Error::new_const(
                            "Missing MASP section reference in action",
                        )
                    })?;

            batched_tx
                .tx
                .get_masp_section(&masp_section_ref)
                .cloned()
                .ok_or_else(|| {
                    Error::new_const("Missing MASP section in transaction")
                })?
        };

        if u64::from(ctx.get_block_height()?)
            > u64::from(shielded_tx.expiry_height())
        {
            let error = Error::new_const("MASP transaction is expired");
            tracing::debug!("{error}");
            return Err(error);
        }

        // Check the validity of the keys and get the transfer data
        let changed_balances = Self::validate_state_and_get_transfer_data(
            ctx,
            keys_changed,
            &tx_data,
        )?;

        // Some constants that will be used repeatedly
        let zero = ValueSum::zero();
        let masp_address_hash = addr_taddr(address::MASP);
        verify_sapling_balancing_value(
            changed_balances
                .pre
                .get(&masp_address_hash)
                .unwrap_or(&zero),
            changed_balances
                .post
                .get(&masp_address_hash)
                .unwrap_or(&zero),
            &changed_balances.undated_pre,
            &changed_balances.undated_post,
            &shielded_tx.sapling_value_balance(),
            masp_epoch,
            &changed_balances.undated_tokens,
            conversion_state,
        )?;

        // The set of addresses that are required to authorize this transaction
        let mut authorizers = BTreeSet::new();

        // Checks on the sapling bundle
        // 1. The spend descriptions' anchors are valid
        // 2. The convert descriptions's anchors are valid
        // 3. The nullifiers provided by the transaction have not been
        // revealed previously (even in the same tx) and no unneeded
        // nullifier is being revealed by the tx
        // 4. The transaction must correctly update the note commitment tree
        // in storage with the new output descriptions
        Self::valid_spend_descriptions_anchor(ctx, &shielded_tx)?;
        Self::valid_convert_descriptions_anchor(ctx, &shielded_tx)?;
        Self::valid_nullifiers_reveal(ctx, keys_changed, &shielded_tx)?;
        Self::valid_note_commitment_update(ctx, &shielded_tx)?;

        // Checks on the transparent bundle, if present
        let mut changed_bals_minus_txn = changed_balances.clone();
        validate_transparent_bundle(
            &shielded_tx,
            &mut changed_bals_minus_txn,
            masp_epoch,
            conversion_state,
            &mut authorizers,
        )?;

        // Ensure that every account for which balance has gone down as a result
        // of the Transaction has authorized this transaction
        for (addr, minus_txn_pre) in changed_bals_minus_txn.pre {
            // The pre-balance seen by all VPs including this one
            let pre = changed_balances.pre.get(&addr).unwrap_or(&zero);
            // The post-balance seen by all VPs including this one
            let post = changed_balances.post.get(&addr).unwrap_or(&zero);
            // The post-balance if the effects of the Transaction are removed
            let minus_txn_post =
                changed_bals_minus_txn.post.get(&addr).unwrap_or(&zero);
            // Never require a signature from the MASP VP
            if addr != masp_address_hash &&
            // Only require further authorization if without the Transaction,
            // this Tx would decrease the balance of this address
                minus_txn_post < &minus_txn_pre &&
            // Only require further authorization from this address if the
            // Transaction alters its balance
                (minus_txn_pre, minus_txn_post) != (pre.clone(), post)
            {
                // This address will need to provide further authorization
                authorizers.insert(addr);
            }
        }

        let mut actions_authorizers: HashSet<&Address> = actions
            .iter()
            .filter_map(|action| {
                if let namada_tx::action::Action::Masp(
                    namada_tx::action::MaspAction::MaspAuthorizer(addr),
                ) = action
                {
                    Some(addr)
                } else {
                    None
                }
            })
            .collect();
        // Ensure that this transaction is authorized by all involved parties
        for authorizer in authorizers {
            if let Some(TAddrData::Addr(address::IBC)) =
                changed_bals_minus_txn.decoder.get(&authorizer)
            {
                // If the IBC address is a signatory, then it means that either
                // Tx - Transaction(s) causes a decrease in the IBC balance or
                // one of the Transactions' transparent inputs is the IBC. We
                // can't check whether such an action has been authorized by the
                // original sender since their address is not in this Namada
                // instance. However, we do know that the overall changes in the
                // IBC state are okay since the IBC VP does check this
                // transaction. So the best we can do is just to ensure that
                // funds intended for the IBC are not being siphoned from the
                // Transactions inside this Tx. We achieve this by not allowing
                // the IBC to be in the transparent output of any of the
                // Transaction(s).
                if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
                    for vout in transp_bundle.vout.iter() {
                        if let Some(TAddrData::Ibc(_)) =
                            changed_bals_minus_txn.decoder.get(&vout.address)
                        {
                            let error = Error::new_const(
                                "Simultaneous credit and debit of IBC account \
                                 in a MASP transaction not allowed",
                            );
                            tracing::debug!("{error}");
                            return Err(error);
                        }
                    }
                }
            } else if let Some(TAddrData::Addr(signer)) =
                changed_bals_minus_txn.decoder.get(&authorizer)
            {
                // Otherwise the owner's vp must have been triggered and the
                // relative action must have been written
                if !verifiers.contains(signer) {
                    let error = Error::new_alloc(format!(
                        "The required vp of address {signer} was not triggered"
                    ));
                    tracing::debug!("{error}");
                    return Err(error);
                }

                // The action is required becuse the target vp might have been
                // triggered for other reasons but we need to signal it that it
                // is required to validate a discrepancy in its balance change
                // because of a masp transaction, which might require a
                // different validation than a normal balance change
                if !actions_authorizers.swap_remove(signer) {
                    let error = Error::new_alloc(format!(
                        "The required masp authorizer action for address \
                         {signer} is missing"
                    ));
                    tracing::debug!("{error}");
                    return Err(error);
                }
            } else {
                // We are not able to decode the authorizer, so just fail
                let error = Error::new_const(
                    "Unable to decode a transaction authorizer",
                );
                tracing::debug!("{error}");
                return Err(error);
            }
        }
        // The transaction shall not push masp authorizer actions that are not
        // needed because this might lead vps to run a wrong validation logic
        if !actions_authorizers.is_empty()
            && shielded_tx
                .transparent_bundle()
                .map(|b| b.vin.is_empty())
                .unwrap_or(true)
        {
            let error = Error::new_const(
                "Found masp authorizer actions that are not required",
            );
            tracing::debug!("{error}");
            return Err(error);
        }

        // Verify the proofs
        verify_shielded_tx(&shielded_tx, |gas| ctx.charge_gas(gas))
    }
}

// Make a map to help recognize asset types lacking an epoch
fn undated_tokens(
    token: &Address,
    denom: token::Denomination,
    tokens: &mut BTreeMap<
        AssetType,
        (Address, token::Denomination, MaspDigitPos),
    >,
) -> Result<()> {
    for digit in MaspDigitPos::iter() {
        let asset_type = encode_asset_type(token.clone(), denom, digit, None)
            .wrap_err("unable to create asset type")?;
        tokens.insert(asset_type, (token.clone(), denom, digit));
    }
    Ok(())
}

fn validate_transparent_input<A: Authorization>(
    vin: &TxIn<A>,
    changed_balances: &mut ChangedBalances,
    transparent_tx_pool: &mut I128Sum,
    epoch: MaspEpoch,
    conversion_state: &ConversionState,
    authorizers: &mut BTreeSet<TransparentAddress>,
) -> Result<()> {
    // A decrease in the balance of an account needs to be
    // authorized by the account of this transparent input
    authorizers.insert(vin.address);
    // Non-masp sources add to the transparent tx pool
    *transparent_tx_pool = transparent_tx_pool
        .checked_add(
            &I128Sum::from_nonnegative(vin.asset_type, i128::from(vin.value))
                .ok()
                .ok_or_err_msg("invalid value or asset type for amount")?,
        )
        .ok_or_err_msg("Overflow in input sum")?;

    let bal_ref = changed_balances
        .pre
        .entry(vin.address)
        .or_insert(ValueSum::zero());

    match conversion_state.assets.get(&vin.asset_type) {
        // Note how the asset's epoch must be equal to the present: users
        // must never be allowed to backdate transparent inputs to a
        // transaction for they would then be able to claim rewards while
        // locking their assets for negligible time periods.
        Some(asset) if asset.epoch == epoch => {
            let amount = token::Amount::from_masp_denominated(
                vin.value,
                asset.digit_pos,
            );
            *bal_ref = bal_ref
                .checked_sub(&ValueSum::from_pair(asset.token.clone(), amount))
                .ok_or_else(|| {
                    Error::new_const("Underflow in bundle balance")
                })?;
        }
        // Maybe the asset type has no attached epoch
        None if changed_balances
            .undated_tokens
            .contains_key(&vin.asset_type) =>
        {
            let (token, denom, digit) =
                &changed_balances.undated_tokens[&vin.asset_type];
            // Determine what the asset type would be if it were dated
            let dated_asset_type =
                encode_asset_type(token.clone(), *denom, *digit, Some(epoch))
                    .wrap_err("unable to create asset type")?;
            if conversion_state.assets.contains_key(&dated_asset_type) {
                // If such a dated asset type is available in the
                // conversion tree, then we must reject the undated
                // variant
                let error =
                    Error::new_const("epoch is missing from asset type");
                tracing::debug!("{error}");
                return Err(error);
            } else {
                // Otherwise note the contribution to this transparent input.
                // This branch represents the case of an asset not being part
                // of the conversion tree: the asset can carry no epoch at all
                // or any epoch (even a future one). Given the way we construct
                // conversions it's not an issue if we later add it to the
                // conversion tree: if the epoch preceeds the one at which we
                // start computing rewards or is missing, then this asset will
                // not be entitled. If it had instead been constructed with a
                // future epoch that matches or follows the one at which we
                // start giving out rewards, then it will be entitled (and
                // there's no issue with that since it was clearly in the pool
                // even before that time)
                let amount =
                    token::Amount::from_masp_denominated(vin.value, *digit);
                *bal_ref = bal_ref
                    .checked_sub(&ValueSum::from_pair(token.clone(), amount))
                    .ok_or_else(|| {
                        Error::new_const("Underflow in bundle balance")
                    })?;
            }
        }
        // unrecognized asset
        _ => {
            let error = Error::new_const("Unable to decode asset type");
            tracing::debug!("{error}");
            return Err(error);
        }
    };
    Ok(())
}

fn validate_transparent_output(
    out: &TxOut,
    changed_balances: &mut ChangedBalances,
    transparent_tx_pool: &mut I128Sum,
    epoch: MaspEpoch,
    conversion_state: &ConversionState,
) -> Result<()> {
    // Non-masp destinations subtract from transparent tx pool
    *transparent_tx_pool = transparent_tx_pool
        .checked_sub(
            &I128Sum::from_nonnegative(out.asset_type, i128::from(out.value))
                .ok()
                .ok_or_err_msg("invalid value or asset type for amount")?,
        )
        .ok_or_err_msg("Underflow in output subtraction")?;

    let bal_ref = changed_balances
        .post
        .entry(out.address)
        .or_insert(ValueSum::zero());

    match conversion_state.assets.get(&out.asset_type) {
        Some(asset) if asset.epoch <= epoch => {
            let amount = token::Amount::from_masp_denominated(
                out.value,
                asset.digit_pos,
            );
            *bal_ref = bal_ref
                .checked_sub(&ValueSum::from_pair(asset.token.clone(), amount))
                .ok_or_else(|| {
                    Error::new_const("Underflow in bundle balance")
                })?;
        }
        // Maybe the asset type has no attached epoch
        None if changed_balances
            .undated_tokens
            .contains_key(&out.asset_type) =>
        {
            // Otherwise note the contribution to this transparent output
            let (token, _denom, digit) =
                &changed_balances.undated_tokens[&out.asset_type];
            let amount =
                token::Amount::from_masp_denominated(out.value, *digit);
            *bal_ref = bal_ref
                .checked_sub(&ValueSum::from_pair(token.clone(), amount))
                .ok_or_else(|| {
                    Error::new_const("Underflow in bundle balance")
                })?;
        }
        // unrecognized asset
        _ => {
            let error = Error::new_const("Unable to decode asset type");
            tracing::debug!("{error}");
            return Err(error);
        }
    };
    Ok(())
}

// Update the transaction value pool and also ensure that the Transaction is
// consistent with the balance changes. I.e. the transparent inputs are not more
// than the initial balances and that the transparent outputs are not more than
// the final balances. Also ensure that the sapling value balance is exactly 0.
fn validate_transparent_bundle(
    shielded_tx: &Transaction,
    changed_balances: &mut ChangedBalances,
    epoch: MaspEpoch,
    conversion_state: &ConversionState,
    authorizers: &mut BTreeSet<TransparentAddress>,
) -> Result<()> {
    // The Sapling value balance adds to the transparent tx pool
    let mut transparent_tx_pool = shielded_tx.sapling_value_balance();

    if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
        for vin in transp_bundle.vin.iter() {
            validate_transparent_input(
                vin,
                changed_balances,
                &mut transparent_tx_pool,
                epoch,
                conversion_state,
                authorizers,
            )?;
        }

        for out in transp_bundle.vout.iter() {
            validate_transparent_output(
                out,
                changed_balances,
                &mut transparent_tx_pool,
                epoch,
                conversion_state,
            )?;
        }
    }

    // Ensure that the shielded transaction exactly balances
    match transparent_tx_pool.partial_cmp(&I128Sum::zero()) {
        None | Some(Ordering::Less) => {
            let error = Error::new_const(
                "Transparent transaction value pool must be nonnegative. \
                 Violation may be caused by transaction being constructed in \
                 previous epoch. Maybe try again.",
            );
            tracing::debug!("{error}");
            // The remaining value in the transparent transaction value pool
            // MUST be nonnegative.
            Err(error)
        }
        Some(Ordering::Greater) => {
            let error = Error::new_const(
                "Transaction fees cannot be left on the MASP balance.",
            );
            tracing::debug!("{error}");
            Err(error)
        }
        _ => Ok(()),
    }
}

// Apply the given Sapling value balance component to the accumulator
fn apply_balance_component(
    acc: &ValueSum<Address, I320>,
    val: i128,
    digit: MaspDigitPos,
    address: Address,
) -> Result<ValueSum<Address, I320>> {
    // Put val into the correct digit position
    let decoded_change = I320::from_masp_denominated(val, digit)
        .map_err(|_| Error::new_const("Overflow in MASP value balance"))?;
    // Tag the numerical change with the token type
    let decoded_change = ValueSum::from_pair(address, decoded_change);
    // Apply the change to the accumulator
    acc.checked_add(&decoded_change)
        .ok_or_else(|| Error::new_const("Overflow in MASP value balance"))
}

// Verify that the pre balance - the Sapling value balance = the post balance
// using the decodings in tokens and conversion_state for assistance.
#[allow(clippy::too_many_arguments)]
fn verify_sapling_balancing_value(
    pre: &ValueSum<Address, Amount>,
    post: &ValueSum<Address, Amount>,
    undated_pre: &ValueSum<Address, Amount>,
    undated_post: &ValueSum<Address, Amount>,
    sapling_value_balance: &I128Sum,
    target_epoch: MaspEpoch,
    tokens: &BTreeMap<AssetType, (Address, token::Denomination, MaspDigitPos)>,
    conversion_state: &ConversionState,
) -> Result<()> {
    let mut acc = ValueSum::<Address, I320>::from_sum(post.clone());
    let mut undated_acc =
        ValueSum::<Address, I320>::from_sum(undated_post.clone());
    for (asset_type, val) in sapling_value_balance.components() {
        // Only assets with at most the target timestamp count
        match conversion_state.assets.get(asset_type) {
            Some(asset) if asset.epoch <= target_epoch => {
                acc = apply_balance_component(
                    &acc,
                    *val,
                    asset.digit_pos,
                    asset.token.clone(),
                )?;
            }
            None if tokens.contains_key(asset_type) => {
                let (token, _denom, digit) = &tokens[asset_type];
                acc =
                    apply_balance_component(&acc, *val, *digit, token.clone())?;
                // Additionally record separately the undated changes
                undated_acc = apply_balance_component(
                    &undated_acc,
                    *val,
                    *digit,
                    token.clone(),
                )?;
            }
            _ => {
                let error = Error::new_const("Unable to decode asset type");
                tracing::debug!("{error}");
                return Err(error);
            }
        }
    }
    if acc != ValueSum::from_sum(pre.clone()) {
        let error = Error::new_const(
            "MASP balance change not equal to Sapling value balance",
        );
        tracing::debug!("{error}");
        Err(error)
    } else if undated_acc != ValueSum::from_sum(undated_pre.clone()) {
        let error = Error::new_const(
            "MASP undated balance change not equal to undated Sapling value \
             balance",
        );
        tracing::debug!("{error}");
        return Err(error);
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod shielded_token_tests {
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    use namada_core::address::MASP;
    use namada_core::address::testing::nam;
    use namada_core::borsh::BorshSerializeExt;
    use namada_gas::{TxGasMeter, VpGasMeter};
    use namada_state::testing::{TestState, arb_account_storage_key, arb_key};
    use namada_state::{StateRead, TxIndex};
    use namada_trans_token::Amount;
    use namada_trans_token::storage_key::balance_key;
    use namada_tx::{BatchedTx, Tx};
    use namada_vm::WasmCacheRwAccess;
    use namada_vm::wasm::VpCache;
    use namada_vm::wasm::compilation_cache::common::testing::vp_cache;
    use namada_vm::wasm::run::VpEvalWasm;
    use namada_vp::native_vp::{self, CtxPostStorageRead, CtxPreStorageRead};
    use namada_vp_env::Error;
    use proptest::proptest;
    use proptest::strategy::Strategy;

    use crate::storage_key::{
        is_masp_key, is_masp_token_map_key, is_masp_transfer_key,
    };

    type CA = WasmCacheRwAccess;
    type Eval<S> = VpEvalWasm<<S as StateRead>::D, <S as StateRead>::H, CA>;
    type Ctx<'ctx, S> = native_vp::Ctx<'ctx, S, VpCache<CA>, Eval<S>>;
    type MaspVp<'ctx, S> = super::MaspVp<
        'ctx,
        Ctx<'ctx, S>,
        namada_parameters::Store<
            CtxPreStorageRead<'ctx, 'ctx, S, VpCache<CA>, Eval<S>>,
        >,
        namada_governance::Store<
            CtxPreStorageRead<'ctx, 'ctx, S, VpCache<CA>, Eval<S>>,
        >,
        namada_ibc::Store<
            CtxPostStorageRead<'ctx, 'ctx, S, VpCache<CA>, Eval<S>>,
        >,
        namada_trans_token::Store<
            CtxPreStorageRead<'ctx, 'ctx, S, VpCache<CA>, Eval<S>>,
        >,
        (),
    >;

    // Changing only the balance key of the MASP is invalid
    #[test]
    fn test_balance_change() {
        let mut state = TestState::default();
        namada_parameters::init_test_storage(&mut state).unwrap();
        let src_key = balance_key(&nam(), &MASP);
        let amount = Amount::native_whole(100);
        let keys_changed = BTreeSet::from([src_key.clone()]);
        let verifiers = Default::default();

        // Initialize MASP balance
        state
            .db_write(&src_key, Amount::native_whole(100).serialize_to_vec())
            .unwrap();

        state.db_write(&src_key, amount.serialize_to_vec()).unwrap();

        let tx_index = TxIndex::default();
        let mut tx = Tx::from_type(namada_tx::data::TxType::Raw);
        tx.push_default_inner_tx();
        let BatchedTx { tx, cmt } = tx.batch_first_tx();

        // Test both credit and debit
        for new_amount in [150, 1] {
            // Update the balance key
            let new_amount = Amount::native_whole(new_amount);
            let _ = state
                .write_log_mut()
                .write(&src_key, new_amount.serialize_to_vec())
                .unwrap();

            let gas_meter =
                RefCell::new(VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                    u64::MAX,
                    namada_parameters::get_gas_scale(&state).unwrap(),
                )));
            let (vp_vp_cache, _vp_cache_dir) = vp_cache();
            let ctx = Ctx::new(
                &MASP,
                &state,
                &tx,
                &cmt,
                &tx_index,
                &gas_meter,
                &keys_changed,
                &verifiers,
                vp_vp_cache,
            );

            // We don't care about the specific error so long as it fails
            assert!(
                MaspVp::validate_tx(
                    &ctx,
                    &tx.batch_ref_tx(&cmt),
                    &keys_changed,
                    &verifiers
                )
                .is_err()
            );
        }
    }

    proptest! {
        // Changing no MASP keys at all is allowed
        #[test]
        fn test_no_masp_op_accepted(src_key in arb_key().prop_filter("MASP key", |key| !is_masp_key(key))) {
            let mut state = TestState::default();
            namada_parameters::init_test_storage(&mut state).unwrap();
            let keys_changed = BTreeSet::from([src_key.clone()]);
            let verifiers = Default::default();

            let tx_index = TxIndex::default();
            let mut tx = Tx::from_type(namada_tx::data::TxType::Raw);
            tx.push_default_inner_tx();
            let BatchedTx { tx, cmt } = tx.batch_first_tx();

            // Write some random value
            let _ = state
                .write_log_mut()
                .write(&src_key, "test".serialize_to_vec())
                .unwrap();

            let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
                &TxGasMeter::new(u64::MAX, namada_parameters::get_gas_scale(&state).unwrap()),
            ));
            let (vp_vp_cache, _vp_cache_dir) = vp_cache();
            let ctx = Ctx::new(
                &MASP,
                &state,
                &tx,
                &cmt,
                &tx_index,
                &gas_meter,
                &keys_changed,
                &verifiers,
                vp_vp_cache,
            );

            assert!(MaspVp::validate_tx(
                &ctx,
                &tx.batch_ref_tx(&cmt),
                &keys_changed,
                &verifiers
            )
            .is_ok());
        }

        // Changing unknown masp keys is not allowed
        #[test]
        fn test_unallowed_masp_keys_rejected(
            random_masp_key in arb_account_storage_key(MASP).prop_filter(
                "MASP valid key",
                |key| !(is_masp_transfer_key(key) || is_masp_token_map_key(key)
            ))
        ) {
            let mut state = TestState::default();
            namada_parameters::init_test_storage(&mut state).unwrap();
            let verifiers = Default::default();

            let tx_index = TxIndex::default();
            let mut tx = Tx::from_type(namada_tx::data::TxType::Raw);
            tx.push_default_inner_tx();
            let BatchedTx { tx, cmt } = tx.batch_first_tx();

            // Write the random masp key
            let _ = state
                .write_log_mut()
                .write(&random_masp_key, "random_value".serialize_to_vec())
                .unwrap();
            let keys_changed = BTreeSet::from([random_masp_key.clone()]);

            let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
                &TxGasMeter::new(u64::MAX, namada_parameters::get_gas_scale(&state).unwrap()),
            ));
            let (vp_vp_cache, _vp_cache_dir) = vp_cache();
            let ctx = Ctx::new(
                &MASP,
                &state,
                &tx,
                &cmt,
                &tx_index,
                &gas_meter,
                &keys_changed,
                &verifiers,
                vp_vp_cache,
            );

            assert!(matches!(
                MaspVp::validate_tx(
                    &ctx,
                    &tx.batch_ref_tx(&cmt),
                    &keys_changed,
                    &verifiers
                ),
                Err(Error::SimpleMessage(
                    "A governance proposal is required to modify MASP \
                    non-transfer keys"
                ))
            ));
        }
    }
}
