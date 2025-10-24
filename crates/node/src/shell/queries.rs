//! Shell methods for querying state

use namada_sdk::queries::{RPC, RequestCtx, ResponseQuery};

use super::*;
use crate::dry_run_tx;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Uses `path` in the query to forward the request to the
    /// right query method and returns the result (which may be
    /// the default if `path` is not a supported string.
    /// INVARIANT: This method must be stateless.
    pub fn query(&self, query: request::Query) -> response::Query {
        // Invoke the root RPC handler - returns borsh-encoded data on success
        let result = if query.path == RPC.shell().dry_run_tx_path() {
            dry_run_tx(
                // This is safe as neither the inner `db` nor `in_mem` are
                // actually mutable, only the `write_log` which is owned by
                // the `TempWlState` struct. The `TempWlState` will be dropped
                // right after dry-run and before any other ABCI request is
                // processed.
                unsafe { self.state.read_only().with_static_temp_write_log() },
                self.vp_wasm_cache.read_only(),
                self.tx_wasm_cache.read_only(),
                &query,
            )
        } else {
            let ctx = RequestCtx {
                state: self.state.read_only(),
                event_log: self.event_log(),
                vp_wasm_cache: self.vp_wasm_cache.read_only(),
                tx_wasm_cache: self.tx_wasm_cache.read_only(),
                storage_read_past_height_limit: self
                    .storage_read_past_height_limit,
            };
            namada_sdk::queries::handle_path(ctx, &query)
        };
        match result {
            Ok(ResponseQuery {
                data,
                info,
                proof,
                height,
            }) => response::Query {
                value: data.into(),
                info,
                proof,
                height: height.0.try_into().expect("Height should be parsable"),
                ..Default::default()
            },
            Err(err) => response::Query {
                code: 1.into(),
                info: format!("RPC error: {}", err),
                ..Default::default()
            },
        }
    }

    /// Simple helper function for the ledger to get balances
    /// of the specified token at the specified address
    pub fn get_balance(
        &self,
        token: &Address,
        owner: &Address,
    ) -> token::Amount {
        // Storage read must not fail, but there might be no value, in which
        // case default (0) is returned
        token::read_balance(&self.state, token, owner)
            .expect("Token balance read in the protocol must not fail")
    }
}

// NOTE: we are testing `namada_sdk::queries_ext`,
// which is not possible from `namada` since we do not have
// access to the `Shell` there
#[allow(clippy::cast_possible_truncation)]
#[cfg(test)]
mod test_queries {
    use namada_sdk::chain::Epoch;
    use namada_sdk::eth_bridge::SendValsetUpd;
    use namada_sdk::eth_bridge::storage::eth_bridge_queries::is_bridge_comptime_enabled;
    use namada_sdk::proof_of_stake::storage::read_consensus_validator_set_addresses_with_stake;
    use namada_sdk::proof_of_stake::types::WeightedValidator;
    use namada_sdk::tendermint::abci::types::VoteInfo;

    use super::*;
    use crate::shell::FinalizeBlockRequest;
    use crate::shell::test_utils::get_pkh_from_address;

    macro_rules! test_must_send_valset_upd {
        (epoch_assertions: $epoch_assertions:expr $(,)?) => {
            /// Test if [`EthBridgeQueries::must_send_valset_upd`] behaves as
            /// expected.
            #[test]
            fn test_must_send_valset_upd() {
                const EPOCH_NUM_BLOCKS: u64 =
                    10 - EPOCH_SWITCH_BLOCKS_DELAY as u64;

                let (mut shell, _recv, _, _oracle_control_recv) =
                    test_utils::setup_at_height(0u64);

                let epoch_assertions = $epoch_assertions;

                let mut prev_epoch = None;

                // test `SendValsetUpd::Now`  and `SendValsetUpd::AtPrevHeight`
                for (curr_epoch, curr_block_height, can_send) in
                    epoch_assertions
                {
                    shell.state
                        .in_mem_mut()
                        .begin_block(curr_block_height.into())
                        .unwrap();

                    if prev_epoch != Some(curr_epoch) {
                        prev_epoch = Some(curr_epoch);
                        shell.start_new_epoch_in(EPOCH_NUM_BLOCKS);
                    }
                    if let Some(b) =
                        shell.state.in_mem_mut().last_block.as_mut()
                    {
                        b.height = BlockHeight(curr_block_height - 1);
                    }
                    assert_eq!(
                        curr_block_height,
                        shell
                            .get_current_decision_height()
                            .0
                    );
                    assert_eq!(
                        shell
                            .state
                            .get_epoch_at_height(curr_block_height.into())
                            .unwrap(),
                        Some(Epoch(curr_epoch))
                    );
                    assert_eq!(
                        shell
                            .state
                            .ethbridge_queries()
                            .must_send_valset_upd(SendValsetUpd::Now),
                        can_send,
                    );
                    let params = read_pos_params::<_, governance::Store<_>>(&shell.state).unwrap();
                    let consensus_set: Vec<WeightedValidator> =
                        read_consensus_validator_set_addresses_with_stake(
                            &shell.state,
                            Epoch::default(),
                        )
                        .unwrap()
                        .into_iter()
                        .collect();

                    let val1 = consensus_set[0].clone();
                    let pkh1 = get_pkh_from_address(
                        &shell.state,
                        &params,
                        val1.address.clone(),
                        Epoch::default(),
                    );
                    let votes = vec![VoteInfo {
                        validator: namada_sdk::tendermint::abci::types::Validator {
                            address: pkh1.clone().into(),
                            power: (u128::try_from(val1.bonded_stake).expect("Test failed") as u64).try_into().unwrap(),
                        },
                        sig_info: namada_sdk::tendermint::abci::types::BlockSignatureInfo::LegacySigned,
                    }];
                    let req = FinalizeBlockRequest {
            proposer_address: tendermint::account::Id::try_from(
                pkh1.to_vec(),
            )
            .unwrap(),
                        decided_last_commit: namada_sdk::tendermint::abci::types::CommitInfo{
                            round: 0u8.into(),
                            votes
                        },
                        ..Default::default()
                    };
                    shell.finalize_and_commit(Some(req));
                }
            }
        };
    }

    const fn send_valset(value: bool) -> bool {
        if !is_bridge_comptime_enabled() {
            false
        } else {
            value
        }
    }

    test_must_send_valset_upd! {
        epoch_assertions: [
            // (current epoch, current block height, must send valset upd)
            // NOTE: can send valset upd on every 2nd block of an epoch
            (0, 1, send_valset(false)),
            (0, 2, send_valset(true)),
            (0, 3, send_valset(false)),
            (0, 4, send_valset(false)),
            (0, 5, send_valset(false)),
            (0, 6, send_valset(false)),
            (0, 7, send_valset(false)),
            (0, 8, send_valset(false)),
            (0, 9, send_valset(false)),
            // we will change epoch here
            (0, 10, send_valset(false)),
            (1, 11, send_valset(true)),
            (1, 12, send_valset(false)),
            (1, 13, send_valset(false)),
            (1, 14, send_valset(false)),
            (1, 15, send_valset(false)),
            (1, 16, send_valset(false)),
            (1, 17, send_valset(false)),
            (1, 18, send_valset(false)),
            (1, 19, send_valset(false)),
            // we will change epoch here
            (1, 20, send_valset(false)),
            (2, 21, send_valset(true)),
            (2, 22, send_valset(false)),
            (2, 23, send_valset(false)),
            (2, 24, send_valset(false)),
            (2, 25, send_valset(false)),
            (2, 26, send_valset(false)),
            (2, 27, send_valset(false)),
            (2, 28, send_valset(false)),
        ],
    }
}
