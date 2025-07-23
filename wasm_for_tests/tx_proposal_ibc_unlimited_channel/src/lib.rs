use namada_tx_prelude::*;

// Channel ID where the transfers are unlimited
const CHANNEL_ID: &str = "channel-0";

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    let unlimited_channel_id = CHANNEL_ID.parse().unwrap();
    let unlimited_channel_key =
        ibc::unlimited_channel_key(&unlimited_channel_id);

    ctx.write(&unlimited_channel_key, unlimited_channel_id)?;

    Ok(())
}
