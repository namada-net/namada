//! The ledger modules

use std::cell::RefCell;

use namada_sdk::borsh::BorshSerializeExt;
use namada_sdk::gas::{GasMetering, TxGasMeter};
use namada_sdk::parameters;
use namada_sdk::queries::{EncodedResponseQuery, RequestQuery};
use namada_sdk::state::{
    DB, DBIter, Error, Result, ResultExt, StorageHasher, TxIndex,
};
use namada_sdk::tx::data::{DryRunResult, GasLimit, TxResult, TxType};
use namada_sdk::tx::{self, Tx};
use namada_vm::WasmCacheAccess;
use namada_vm::wasm::{TxCache, VpCache};

use crate::protocol;
use crate::protocol::ShellParams;

/// Dry run a transaction
pub fn dry_run_tx<D, H, CA>(
    mut state: namada_sdk::state::TempWlState<'static, D, H>,
    mut vp_wasm_cache: VpCache<CA>,
    mut tx_wasm_cache: TxCache<CA>,
    request: &RequestQuery,
) -> Result<EncodedResponseQuery>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let tx = Tx::try_from_bytes(&request.data[..]).into_storage_result()?;

    let gas_scale = parameters::get_gas_scale(&state)?;
    let height = state.in_mem().get_block_height().0;

    // Wrapper dry run to allow estimating the entire gas cost of a transaction
    let (wrapper_hash, tx_result, tx_gas_meter) = match tx.header().tx_type {
        TxType::Wrapper(wrapper) => {
            let gas_limit = wrapper
                .gas_limit
                .as_scaled_gas(gas_scale)
                .into_storage_result()?;
            let tx_gas_meter =
                RefCell::new(TxGasMeter::new(gas_limit, gas_scale));
            let mut shell_params = ShellParams::new(
                &tx_gas_meter,
                &mut state,
                &mut vp_wasm_cache,
                &mut tx_wasm_cache,
            );
            let tx_result = protocol::apply_wrapper_tx(
                &tx,
                &wrapper,
                &request.data,
                TxIndex::default(),
                height,
                &tx_gas_meter,
                &mut shell_params,
                None,
                true,
            )
            .into_storage_result()?;

            state.write_log_mut().commit_tx_to_batch();
            (Some(tx.header_hash()), tx_result, tx_gas_meter)
        }
        _ => {
            // Check allowlist as the wasm vm `fn check_tx_allowed` is only
            // enforced for wrappers
            for cmt in tx.commitments() {
                let code_sec = tx
                    .get_section(cmt.code_sechash())
                    .and_then(|x| tx::Section::code_sec(&x))
                    .ok_or_else(|| Error::new_const("Missing tx code"))?;
                let code_hash = code_sec.code.hash();
                if !parameters::is_tx_allowed(&state, &code_hash)? {
                    return Err(Error::new_alloc(format!(
                        "Tx code with hash {} is disallowed",
                        code_hash.to_string().to_lowercase()
                    )));
                }
            }

            // When dry running only the inner tx(s), use the max block gas
            // as the gas limit
            let max_block_gas = parameters::get_max_block_gas(&state)?;
            let gas_limit = GasLimit::from(max_block_gas)
                .as_scaled_gas(gas_scale)
                .into_storage_result()?;
            (
                None,
                TxResult::default(),
                RefCell::new(TxGasMeter::new(gas_limit, gas_scale)),
            )
        }
    };

    let tx_result = protocol::dispatch_inner_txs(
        &tx,
        wrapper_hash.as_ref(),
        tx_result,
        TxIndex(0),
        height,
        &tx_gas_meter,
        &mut state,
        &mut vp_wasm_cache,
        &mut tx_wasm_cache,
        protocol::GasMeterKind::MutGlobal,
        true,
    )
    .map_err(|err| err.error)
    .into_storage_result()?;
    let tx_result_string = tx_result.to_result_string();
    let dry_run_result = DryRunResult(
        tx_result_string,
        tx_gas_meter
            .borrow()
            .get_consumed_gas()
            .get_whole_gas_units(gas_scale),
    );

    Ok(EncodedResponseQuery {
        data: dry_run_result.serialize_to_vec(),
        proof: None,
        info: Default::default(),
        height,
    })
}

#[cfg(test)]
mod test {
    use namada_sdk::borsh::{BorshDeserialize, BorshSerializeExt};
    use namada_sdk::chain::BlockHeight;
    use namada_sdk::events::log::EventLog;
    use namada_sdk::hash::Hash;
    use namada_sdk::io::Client;
    use namada_sdk::queries::{
        EncodedResponseQuery, RPC, RequestCtx, RequestQuery, Router,
    };
    use namada_sdk::state::StorageWrite;
    use namada_sdk::state::testing::TestState;
    use namada_sdk::storage::Key;
    use namada_sdk::tendermint_rpc::{Error as RpcError, Response};
    use namada_sdk::tx::data::TxType;
    use namada_sdk::tx::{Code, Data, Tx};
    use namada_sdk::{address, token};
    use namada_test_utils::TestWasms;
    use namada_vm::wasm::{TxCache, VpCache};
    use namada_vm::{WasmCacheRoAccess, wasm};
    use tempfile::TempDir;

    use super::*;

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
        /// VP wasm compilation cache
        pub vp_wasm_cache: VpCache<WasmCacheRoAccess>,
        /// tx wasm compilation cache
        pub tx_wasm_cache: TxCache<WasmCacheRoAccess>,
        /// VP wasm compilation cache directory
        #[allow(dead_code)] // never read
        pub vp_cache_dir: TempDir,
        /// tx wasm compilation cache directory
        #[allow(dead_code)] // never read
        pub tx_cache_dir: TempDir,
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
                namada_sdk::parameters::storage::get_max_block_gas_key();
            state
                .db_write(&max_block_gas_key, 20_000_000_u64.serialize_to_vec())
                .expect(
                    "Max block gas parameter must be initialized in storage",
                );
            // Initialize mock gas scale
            let gas_scale_key = parameters::storage::get_gas_scale_key();
            state
                .db_write(&gas_scale_key, 100_000_000_u64.serialize_to_vec())
                .expect("Gas scale parameter must be initialized in storage");

            let event_log = EventLog::default();
            let (vp_wasm_cache, vp_cache_dir) =
                wasm::compilation_cache::common::testing::cache();
            let (tx_wasm_cache, tx_cache_dir) =
                wasm::compilation_cache::common::testing::cache();
            Self {
                rpc,
                state,
                event_log,
                vp_wasm_cache: vp_wasm_cache.read_only(),
                tx_wasm_cache: tx_wasm_cache.read_only(),
                vp_cache_dir,
                tx_cache_dir,
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl<RPC> Client for TestClient<RPC>
    where
        RPC: Router + Sync,
    {
        type Error = std::io::Error;

        async fn request(
            &self,
            path: String,
            data: Option<Vec<u8>>,
            height: Option<BlockHeight>,
            prove: bool,
        ) -> std::result::Result<EncodedResponseQuery, Self::Error> {
            let data = data.unwrap_or_default();
            let height = height.unwrap_or_default();
            // Handle a path by invoking the `RPC.handle` directly with the
            // borrowed storage
            let request = RequestQuery {
                data: data.into(),
                path,
                height: height.try_into().unwrap(),
                prove,
            };
            // TODO(namada#3240): this is a hack to propagate errors to the
            // caller, we should really permit error types other
            // than [`std::io::Error`]
            if request.path == RPC.shell().dry_run_tx_path() {
                dry_run_tx(
                    // This is safe because nothing else is using `self.state`
                    // concurrently and the `TempWlState` will be dropped right
                    // after dry-run.
                    unsafe {
                        self.state.read_only().with_static_temp_write_log()
                    },
                    self.vp_wasm_cache.clone(),
                    self.tx_wasm_cache.clone(),
                    &request,
                )
            } else {
                let ctx = RequestCtx {
                    state: self.state.read_only(),
                    event_log: &self.event_log,
                    vp_wasm_cache: self.vp_wasm_cache.clone(),
                    tx_wasm_cache: self.tx_wasm_cache.clone(),
                    storage_read_past_height_limit: None,
                };
                self.rpc.handle(ctx, &request)
            }
            .map_err(|err| std::io::Error::other(err.to_string()))
        }

        async fn perform<R>(
            &self,
            _request: R,
        ) -> std::result::Result<R::Output, RpcError>
        where
            R: namada_sdk::tendermint_rpc::SimpleRequest,
        {
            Ok(R::Response::from_string("TODO").unwrap().into())
        }
    }

    #[tokio::test]
    async fn test_shell_queries_router_with_client() -> Result<()> {
        // Initialize the `TestClient`
        let mut client = TestClient::new(RPC);
        // store the wasm code
        let tx_no_op = TestWasms::TxNoOp.read_bytes();
        let tx_hash = Hash::sha256(&tx_no_op);
        let key = Key::wasm_code(&tx_hash);
        let len_key = Key::wasm_code_len(&tx_hash);
        client
            .state
            .db_write(&key, tx_no_op.serialize_to_vec())
            .unwrap();
        client
            .state
            .db_write(&len_key, (tx_no_op.len() as u64).serialize_to_vec())
            .unwrap();

        // Request last committed epoch
        let read_epoch = RPC.shell().epoch(&client).await.unwrap();
        let current_epoch = client.state.in_mem().last_epoch;
        assert_eq!(current_epoch, read_epoch);

        // Request dry run tx
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = client.state.in_mem().chain_id.clone();
        outer_tx.set_code(Code::from_hash(tx_hash, None));
        outer_tx.set_data(Data::new(vec![]));
        let cmt = outer_tx.first_commitments().unwrap();
        let tx_bytes = outer_tx.to_bytes();
        let result = RPC
            .shell()
            .dry_run_tx(&client, Some(tx_bytes), None, false)
            .await
            .unwrap();
        assert!(
            result
                .data
                .0
                .get_inner_tx_result(None, either::Right(cmt))
                .unwrap()
                .as_ref()
                .unwrap()
                .is_accepted()
        );

        // Request storage value for a balance key ...
        let token_addr = address::testing::established_address_1();
        let owner = address::testing::established_address_2();
        let balance_key = token::storage_key::balance_key(&token_addr, &owner);
        // ... there should be no value yet.
        let read_balance = RPC
            .shell()
            .storage_value(&client, None, None, false, &balance_key)
            .await
            .unwrap();
        assert!(read_balance.data.is_empty());

        // Request storage prefix iterator
        let balance_prefix = token::storage_key::balance_prefix(&token_addr);
        let read_balances = RPC
            .shell()
            .storage_prefix(&client, None, None, false, &balance_prefix)
            .await
            .unwrap();
        assert!(read_balances.data.is_empty());

        // Request storage has key
        let has_balance_key = RPC
            .shell()
            .storage_has_key(&client, &balance_key)
            .await
            .unwrap();
        assert!(!has_balance_key);

        // Then write some balance ...
        let balance = token::Amount::native_whole(1000);
        StorageWrite::write(&mut client.state, &balance_key, balance)?;
        // It has to be committed to be visible in a query
        client.state.commit_tx_batch();
        client.state.commit_block().unwrap();
        // ... there should be the same value now
        let read_balance = RPC
            .shell()
            .storage_value(&client, None, None, false, &balance_key)
            .await
            .unwrap();
        assert_eq!(
            balance,
            token::Amount::try_from_slice(&read_balance.data).unwrap()
        );

        // Request storage prefix iterator
        let balance_prefix = token::storage_key::balance_prefix(&token_addr);
        let read_balances = RPC
            .shell()
            .storage_prefix(&client, None, None, false, &balance_prefix)
            .await
            .unwrap();
        assert_eq!(read_balances.data.len(), 1);

        // Request storage has key
        let has_balance_key = RPC
            .shell()
            .storage_has_key(&client, &balance_key)
            .await
            .unwrap();
        assert!(has_balance_key);

        Ok(())
    }
}
