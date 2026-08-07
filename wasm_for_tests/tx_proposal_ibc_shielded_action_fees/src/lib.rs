use namada_tx_prelude::*;

use self::dec::Dec;

// trace path of the token
const TRACE_PATH: &str = "transfer/channel-0/samoleans";

// 1% shielding fees
const SHIELDING_FEES: &str = "0.01";

// 2% unshielding fees
const UNSHIELDING_FEES: &str = "0.02";

#[transaction]
fn apply_tx(ctx: &mut Ctx, _: BatchedTx) -> TxResult {
    let ibc_token = ibc::ibc_token(TRACE_PATH);

    let shielding_fees_key =
        parameters_storage::get_masp_over_ibc_shielding_fees_of_token_key(
            &ibc_token,
        );
    let unshielding_fees_key =
        parameters_storage::get_masp_over_ibc_unshielding_fees_of_token_key(
            &ibc_token,
        );

    ctx.write(
        &shielding_fees_key,
        SHIELDING_FEES.parse::<Dec>().unwrap(),
    )?;
    ctx.write(
        &unshielding_fees_key,
        UNSHIELDING_FEES.parse::<Dec>().unwrap(),
    )?;

    Ok(())
}
