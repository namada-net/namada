use std::str::FromStr;

use dec::Dec;
use namada_proof_of_stake::storage::{read_pos_params, write_pos_params};
use namada_tx_prelude::hash::Hash;
use namada_tx_prelude::storage::Key;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    // governance
    let target_key = gov_storage::keys::get_min_proposal_grace_epochs_key();
    ctx.write(&target_key, 9_u64)?;

    // parameters
    let target_key = parameters_storage::get_vp_allowlist_storage_key();
    ctx.write(&target_key, vec!["hash"])?;

    // add tx
    let wasm_code_hash = Hash::sha256("test");
    let wasm_code_name = "test".to_string();

    let wasm_code_key = Key::wasm_code(&wasm_code_hash);
    ctx.write_bytes(&wasm_code_key, [])?;

    let wasm_code_len_key = Key::wasm_code_len(&wasm_code_hash);
    ctx.write(&wasm_code_len_key, 30.serialize_to_vec())?;

    let wasm_code_hash_key = Key::wasm_code_hash("test".to_string());
    ctx.write_bytes(&wasm_code_hash_key, wasm_code_hash)?;

    let wasm_code_name_key = Key::wasm_code_name(&wasm_code_hash);
    ctx.write_bytes(&wasm_code_name_key, &wasm_code_name)?;

    let wasm_hash_key = Key::wasm_hash("test");
    ctx.write_bytes(&wasm_hash_key, wasm_code_name)?;

    // change pgf parameter
    let pgf_inflation_key =
        governance::pgf::storage::keys::get_pgf_inflation_rate_key();
    let pgf_inflation_rate = Dec::from_str("0.025").unwrap();
    ctx.write(&pgf_inflation_key, pgf_inflation_rate)?;

    // change pos parameter
    let mut pos_params = read_pos_params::<_, governance::Store<_>>(ctx)?.owned;
    pos_params.max_inflation_rate = Dec::from_str("0.15").unwrap();
    pos_params.target_staked_ratio = Dec::from_str("0.33").unwrap();
    pos_params.rewards_gain_p = Dec::from_str("1.5").unwrap();
    pos_params.rewards_gain_d = Dec::from_str("3.5").unwrap();
    write_pos_params(ctx, &pos_params)?;

    // change ibc parameter
    let ibc_denom = "transfer/channel-0/some_token_address".to_string();
    let token_address = ibc::ibc_token(ibc_denom);

    let mint_limit_token_key = ibc::mint_limit_key(&token_address);
    ctx.write(&mint_limit_token_key, token::Amount::from_u64(100))?;

    let throughput_limit_token_key = ibc::throughput_limit_key(&token_address);
    ctx.write(&throughput_limit_token_key, token::Amount::from_u64(100))?;

    Ok(())
}
