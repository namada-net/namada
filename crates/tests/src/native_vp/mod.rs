pub mod escrow_drain;
pub mod eth_bridge_pool;
pub mod overflow_recv;
pub mod pos;
pub mod pos_unbacked_bond;

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

#[cfg(test)]
mod test_inner_tx_sections {
    use namada_sdk::gas::TxGasMeter;
    use namada_sdk::tx::data::TxType;
    use namada_sdk::tx::{Code, Data, Tx};
    use namada_vm::wasm::compilation_cache::common::testing::vp_cache;
    use namada_vp::VpEnv;

    use super::*;

    /// Check that a native VP ctx with the inner tx sections looked up from
    /// the batch indices behaves exactly like one looking them up from the tx,
    /// including the gas it charges
    #[test]
    fn test_native_ctx_inner_tx_sections_equivalent() {
        let state = TestState::default();
        let (vp_wasm_cache, _dir) = vp_cache();
        let address = namada_sdk::address::testing::established_address_1();
        let tx_index = storage::TxIndex::default();
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();

        let mut tx = Tx::from_type(TxType::Raw);
        tx.set_code(Code::new(b"code 1".to_vec(), None));
        tx.set_data(Data::new(b"data 1".to_vec()));
        tx.push_default_inner_tx();
        tx.set_code(Code::new(b"code 2".to_vec(), None));
        tx.set_data(Data::new(b"data 2".to_vec()));
        // An inner tx with neither code nor data sections
        tx.push_default_inner_tx();
        assert_eq!(tx.commitments().len(), 3);

        let batch_sections = tx.batch_sections();

        for cmt in tx.commitments() {
            let run = |with_sections: bool| {
                let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
                    &TxGasMeter::new(u64::MAX, 1),
                ));
                let mut ctx = NativeVpCtx::new(
                    &address,
                    &state,
                    &tx,
                    cmt,
                    &tx_index,
                    &gas_meter,
                    &keys_changed,
                    &verifiers,
                    vp_wasm_cache.clone(),
                    GasMeterKind::MutGlobal,
                );
                if with_sections {
                    ctx = ctx
                        .with_inner_tx_sections(batch_sections.inner_tx(cmt));
                }
                let code_hash = ctx.get_tx_code_hash().unwrap();
                // The data of every inner tx, including the ones that are not
                // being validated by this ctx
                let data: Vec<_> = tx
                    .commitments()
                    .iter()
                    .map(|other| ctx.get_tx_data(&tx.batch_ref_tx(other)))
                    .collect();
                drop(ctx);
                let gas = gas_meter.into_inner().get_vp_consumed_gas();
                (code_hash, data, gas)
            };
            let expected = run(false);
            assert_eq!(run(true), expected);
            assert_eq!(expected.1.len(), 3);
        }
    }
}

/// Gets the absolute path to the wasm directory
#[cfg(test)]
pub fn wasm_dir() -> std::path::PathBuf {
    let mut current_path = std::env::current_dir()
        .expect("Current directory should exist")
        .canonicalize()
        .expect("Current directory should exist");
    while current_path.file_name().unwrap() != "tests" {
        current_path.pop();
    }
    // Two-dirs up to root
    current_path.pop();
    current_path.pop();
    current_path.join("wasm")
}

/// Sign the given tx's sections and wrapper with a test keypair
#[cfg(test)]
pub fn sign_tx(tx: &mut namada_sdk::tx::Tx) {
    use namada_sdk::account::AccountPublicKeysMap;
    use namada_sdk::key::{self, RefTo};

    let keypair = key::testing::keypair_1();
    let pks_map = AccountPublicKeysMap::from_iter([keypair.ref_to()]);
    tx.sign_raw(vec![keypair.clone()], pks_map, None)
        .sign_wrapper(keypair);
}
