//! A tx for IBC.
//! This tx executes an IBC operation according to the given IBC message as the
//! tx_data. This tx uses an IBC message as its input.

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let data = ibc::ibc_actions(ctx)
        .execute::<token::Transfer>(&data)
        .into_storage_result()?;

    let (masp_section_ref, mut token_addrs) =
        if let Some(transfers) = data.transparent {
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
            (None, Default::default())
        };

    token_addrs.extend(data.ibc_tokens);

    let (shielded, seq) = if let Some(masp_section_ref) = masp_section_ref {
        (
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
            ),
            None,
        )
    } else {
        data.shielded.unzip()
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
            match shielded {
                ShieldingData::Tx(_) => {
                    ctx.push_action(Action::IbcShielding)?
                }
                ShiedlingData::Note(notes) => {
                    ctx.push_action(Action::IbcMinedNotes(
                        notes
                            .iter()
                            .map(|note| IbcMinedNote {
                                asset_type: note.asset_type,
                                seq: seq.unwrap(),
                            })
                            .collect(),
                    ))
                }
            }
        }
        token::update_undated_balances(ctx, &shielded, token_addrs)?;
    }

    Ok(())
}
