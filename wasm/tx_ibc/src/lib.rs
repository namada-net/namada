//! A tx for IBC.
//! This tx executes an IBC operation according to the given IBC message as the
//! tx_data. This tx uses an IBC message as its input.

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::address::MASP;
use namada_tx_prelude::masp::{AssetData, MaspEpoch};
use namada_tx_prelude::parameters_storage::get_masp_epoch_multiplier_key;
use namada_tx_prelude::token::storage_key::denom_key;
use namada_tx_prelude::token::{
    Amount, DenominatedAmount, MaspDigitPos, Transfer,
};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let data = ibc::ibc_actions(ctx)
        .execute::<token::Transfer>(&data)
        .into_storage_result()?;

    let (masp_section_ref, mut token_addrs) = if let Some(transfers) =
        data.transparent
    {
        let (_debited_accounts, tokens) =
            if let Some(transparent) = transfers.transparent_part() {
                token::validate_transfer_in_out(
                    transparent.sources,
                    transparent.targets,
                )
                .map_err(Error::new_alloc)?;

                token::apply_transparent_transfers(ctx, transparent)
                    .wrap_err("Transparent token transfer failed")?
            } else {
                Default::default()
            };

        (transfers.shielded_section_hash, tokens)
    } else {
        // Execute the transparent part of the incoming IBC packet if present
        // FIXME: don't need to encode the fee in the transparent part, it's
        // just the difference between what we shield and what we minted in the
        // ibc packet. But we'd need to provide this wasm code with additional
        // information. I would need this amount. It's probably just better to
        // generalize the transparent transfer
        let tokens = if let Some((shielded, Some(target))) = &data.shielded {
            // Extra required transparent transfer for frontend MASP fees
            let (raw_amt, asset_type) = shielded
                .transparent_bundle()
                .and_then(|bundle| {
                    bundle
                        .vout
                        .first()
                        .map(|vout| (vout.value, vout.asset_type))
                })
                .ok_or_err_msg(
                    "Missing expected transparent output for incoming IBC \
                     packet",
                )?;
            let token = data.ibc_tokens.first().ok_or_err_msg(
                "Missing expected token for incoming IBC packet",
            )?;
            let denomination = ctx
                .read(&denom_key(token))?
                .unwrap_or(token::Denomination(0));
            let epoch = ctx.get_block_epoch()?;
            let masp_epoch_multiplier = ctx
                .read(&get_masp_epoch_multiplier_key())?
                .ok_or_err_msg("Missing masp epoch multiplier in storage")?;

            let current_masp_epoch = Some(
                MaspEpoch::try_from_epoch(epoch, masp_epoch_multiplier)
                    .map_err(|_| {
                        Error::SimpleMessage(
                            "Failed to construct the current MASP epoch",
                        )
                    })?,
            );
            let mut masp_digit_pos = None;
            for epoch in [None, current_masp_epoch] {
                for position in MaspDigitPos::iter() {
                    let asset_data = AssetData {
                        token: token.to_owned(),
                        denom: denomination,
                        position,
                        epoch,
                    };

                    if asset_data.encode().wrap_err(
                        "Failed to encode masp frontend sus fee asset type",
                    )? == asset_type
                    {
                        masp_digit_pos = Some(position);
                        break;
                    }
                }
            }

            let masp_digit_pos = masp_digit_pos.ok_or_err_msg(
                "Could not find a matching masp digit position",
            )?;
            let amt = Amount::from_masp_denominated(raw_amt, masp_digit_pos);
            let denominated_amount = DenominatedAmount::new(amt, denomination);
            let transfer = Transfer::default();
            // The amount for the masp frontend fee has been minted to the MASP
            // account, we need to move it to the intended recipient
            let transfer = transfer
                .transfer(
                    MASP,
                    target.to_owned(),
                    token.to_owned(),
                    denominated_amount,
                )
                .ok_or_err_msg(
                    "Failed to construct transparent transfer for MASP \
                     frontend sustainability fee",
                )?;
            let transparent = transfer.transparent_part().unwrap();
            let (_, tokens) =
                token::apply_transparent_transfers(ctx, transparent).wrap_err(
                    "Transparent token transfer from IBC packet failed",
                )?;

            tokens
        } else {
            Default::default()
        };

        (None, tokens)
    };

    token_addrs.extend(data.ibc_tokens);

    let shielded = if let Some(masp_section_ref) = masp_section_ref {
        Some(
            tx_data
                .tx
                .get_masp_section(&masp_section_ref)
                .cloned()
                .ok_or_err_msg(
                    "Unable to find required shielded section in tx data",
                )
                .inspect_err(|_| {
                    ctx.set_commitment_sentinel();
                })?,
        )
    } else {
        data.shielded.map(|(shielded, _)| shielded)
    };
    if let Some(shielded) = shielded {
        token::utils::handle_masp_tx(ctx, &shielded)
            .wrap_err("Encountered error while handling MASP transaction")?;
        update_masp_note_commitment_tree(&shielded)
            .wrap_err("Failed to update the MASP commitment tree")?;
        if let Some(masp_section_ref) = masp_section_ref {
            ctx.push_action(Action::Masp(MaspAction::MaspSectionRef(
                masp_section_ref,
            )))?;
        } else {
            ctx.push_action(Action::IbcShielding)?;
        }
        token::update_undated_balances(ctx, &shielded, token_addrs)?;
    }

    Ok(())
}
