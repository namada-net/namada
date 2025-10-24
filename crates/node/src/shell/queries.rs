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
