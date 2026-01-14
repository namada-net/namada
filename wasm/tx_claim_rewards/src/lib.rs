//! A tx for a user to claim PoS inflationary rewards due to bonds used as
//! voting power in consensus.

use namada_tx_prelude::transaction::pos;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let (validator, source, receiver) = if let Ok(pos::ClaimRewards {
        validator,
        source,
        receiver,
    }) =
        pos::ClaimRewards::try_from_slice(&data[..])
    {
        (validator, source, receiver)
    } else {
        let pos::ClaimRewardsCompat { validator, source } =
            pos::ClaimRewardsCompat::try_from_slice(&data[..])
                .wrap_err("Failed to decode ClaimRewards value")?;
        (validator, source, None)
    };
    ctx.claim_reward_tokens(source.as_ref(), &validator, receiver.as_ref())
        .wrap_err("Failed to claim rewards")?;

    Ok(())
}
