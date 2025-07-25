pub mod eth_bridge_pool;
pub mod pos;

use std::cell::RefCell;
use std::collections::BTreeSet;

use namada_sdk::address::Address;
use namada_sdk::gas::{GasMeterKind, VpGasMeter};
use namada_sdk::state::StateRead;
use namada_sdk::state::testing::TestState;
use namada_sdk::storage;
use namada_vm::WasmCacheRwAccess;
use namada_vm::wasm::VpCache;
use namada_vm::wasm::run::VpEvalWasm;
use namada_vp::native_vp::{self, Ctx, NativeVp};

use crate::tx::TestTxEnv;

type NativeVpCtx<'a> = Ctx<
    'a,
    TestState,
    VpCache<WasmCacheRwAccess>,
    VpEvalWasm<
        <TestState as StateRead>::D,
        <TestState as StateRead>::H,
        WasmCacheRwAccess,
    >,
>;

#[derive(Debug)]
pub struct TestNativeVpEnv {
    pub tx_env: TestTxEnv,
    pub address: Address,
    pub verifiers: BTreeSet<Address>,
    pub keys_changed: BTreeSet<storage::Key>,
}

impl TestNativeVpEnv {
    pub fn from_tx_env(tx_env: TestTxEnv, address: Address) -> Self {
        // Find the tx verifiers and keys_changes the same way as protocol would
        let verifiers = tx_env.get_verifiers();

        let keys_changed = tx_env.all_touched_storage_keys();

        Self {
            address,
            tx_env,
            verifiers,
            keys_changed,
        }
    }
}

impl TestNativeVpEnv {
    /// Run some transaction code `apply_tx` and validate it with a native VP
    pub fn init_vp<'view, 'ctx: 'view, T>(
        &'ctx self,
        gas_meter: &'ctx RefCell<VpGasMeter>,
        init_native_vp: impl Fn(NativeVpCtx<'ctx>) -> T,
    ) -> T
    where
        T: NativeVp<'view>,
    {
        let ctx = NativeVpCtx::new(
            &self.address,
            &self.tx_env.state,
            &self.tx_env.batched_tx.tx,
            &self.tx_env.batched_tx.cmt,
            &self.tx_env.tx_index,
            gas_meter,
            &self.keys_changed,
            &self.verifiers,
            self.tx_env.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        );
        init_native_vp(ctx)
    }

    /// Instantiate a native VP ctx to run a VP
    pub fn ctx<'ctx>(
        &'ctx self,
        gas_meter: &'ctx RefCell<VpGasMeter>,
    ) -> NativeVpCtx<'ctx> {
        NativeVpCtx::new(
            &self.address,
            &self.tx_env.state,
            &self.tx_env.batched_tx.tx,
            &self.tx_env.batched_tx.cmt,
            &self.tx_env.tx_index,
            gas_meter,
            &self.keys_changed,
            &self.verifiers,
            self.tx_env.vp_wasm_cache.clone(),
            GasMeterKind::MutGlobal,
        )
    }

    /// Run some transaction code `apply_tx` and validate it with a native VP
    pub fn validate_tx<'view, 'ctx: 'view, T>(
        &'ctx self,
        vp: &'view T,
    ) -> native_vp::Result<()>
    where
        T: 'view + NativeVp<'view>,
    {
        vp.validate_tx(
            &self.tx_env.batched_tx.to_ref(),
            &self.keys_changed,
            &self.verifiers,
        )
    }
}
