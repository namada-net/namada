//! Ledger read-only queries can be handled and dispatched via the [`RPC`]
//! defined via `router!` macro.

// Re-export to show in rustdoc!
use namada_state::{DB, DBIter, StorageHasher};
use shell::SHELL;
pub use shell::Shell;
pub use types::{
    EncodedResponseQuery, Error, RequestCtx, RequestQuery, ResponseQuery,
    Router,
};
use vp::{VP, Vp};

#[macro_use]
mod router;
mod shell;
mod types;
pub mod vp;

// Most commonly expected patterns should be declared first
router! {RPC,
    // Shell provides storage read access, block metadata and can dry-run a tx
    ( "shell" ) = (sub SHELL),

    // Validity-predicate's specific storage queries
    ( "vp" ) = (sub VP),
}

/// Handle RPC query request in the ledger. On success, returns response with
/// borsh-encoded data.
pub fn handle_path<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    request: &RequestQuery,
) -> namada_storage::Result<EncodedResponseQuery>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    RPC.handle(ctx, request)
}

// Handler helpers:

/// For queries that only support latest height, check that the given height is
/// not different from latest height, otherwise return an error.
pub fn require_latest_height<D, H, V, T>(
    ctx: &RequestCtx<'_, D, H, V, T>,
    request: &RequestQuery,
) -> namada_storage::Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if request.height.value() != 0
        && request.height.value()
            != ctx.state.in_mem().get_last_block_height().0
    {
        return Err(namada_storage::Error::new_const(
            "This query doesn't support arbitrary block heights, only the \
             latest committed block height ('0' can be used as a special \
             value that means the latest block height)",
        ));
    }
    Ok(())
}

/// For queries that do not support proofs, check that proof is not requested,
/// otherwise return an error.
pub fn require_no_proof(request: &RequestQuery) -> namada_storage::Result<()> {
    if request.prove {
        return Err(namada_storage::Error::new_const(
            "This query doesn't support proofs",
        ));
    }
    Ok(())
}

/// For queries that don't use request data, require that there are no data
/// attached.
pub fn require_no_data(request: &RequestQuery) -> namada_storage::Result<()> {
    if !request.data.is_empty() {
        return Err(namada_storage::Error::new_const(
            "This query doesn't accept request data",
        ));
    }
    Ok(())
}

/// Queries testing helpers
#[cfg(any(test, feature = "testing"))]
pub(crate) mod testing {
    use namada_core::chain::BlockHeight;
    use namada_io::client::Client;
    use namada_state::testing::TestState;
    use tendermint_rpc::Response;

    use super::*;
    use crate::borsh::BorshSerializeExt;
    use crate::events::log::EventLog;
    use crate::tendermint_rpc::error::Error as RpcError;

    /// A test client that has direct access to the storage
    pub struct TestClient<RPC>
    where
        RPC: Router,
    {
        /// RPC router
        pub rpc: RPC,
        /// state
        pub state: TestState,
        /// event log
        pub event_log: EventLog,
    }

    impl<RPC> TestClient<RPC>
    where
        RPC: Router,
    {
        #[allow(dead_code)]
        /// Initialize a test client for the given root RPC router
        pub fn new(rpc: RPC) -> Self {
            // Initialize the `TestClient`
            let mut state = TestState::default();

            // Initialize mock gas limit
            let max_block_gas_key =
                namada_parameters::storage::get_max_block_gas_key();
            state
                .db_write(&max_block_gas_key, 20_000_000_u64.serialize_to_vec())
                .expect(
                    "Max block gas parameter must be initialized in storage",
                );
            let event_log = EventLog::default();
            Self {
                rpc,
                state,
                event_log,
            }
        }
    }

    #[cfg_attr(feature = "async-send", async_trait::async_trait)]
    #[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
    impl<RPC> Client for TestClient<RPC>
    where
        RPC: Router + crate::MaybeSync,
    {
        type Error = std::io::Error;

        async fn request(
            &self,
            path: String,
            data: Option<Vec<u8>>,
            height: Option<BlockHeight>,
            prove: bool,
        ) -> Result<EncodedResponseQuery, Self::Error> {
            let data = data.unwrap_or_default();
            let height = height.unwrap_or_default();
            let height: crate::tendermint::block::Height =
                height.try_into().map_err(|err| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
                })?;
            // Handle a path by invoking the `RPC.handle` directly with the
            // borrowed storage
            let request = RequestQuery {
                data: data.into(),
                path,
                height,
                prove,
            };
            let ctx = RequestCtx {
                state: self.state.read_only(),
                event_log: &self.event_log,
                vp_wasm_cache: (),
                tx_wasm_cache: (),
                storage_read_past_height_limit: None,
            };
            self.rpc
                .handle(ctx, &request)
                .map_err(|err| std::io::Error::other(err.to_string()))
        }

        async fn perform<R>(&self, _request: R) -> Result<R::Output, RpcError>
        where
            R: tendermint_rpc::SimpleRequest,
        {
            Ok(R::Response::from_string("TODO").unwrap().into())
        }
    }
}
