use std::cell::RefCell;
use std::collections::BTreeSet;

use namada_sdk::address::{self, Address};
use namada_sdk::gas::{TxGasMeter, VpGasMeter};
use namada_sdk::state::mockdb::MockDB;
use namada_sdk::state::prefix_iter::PrefixIterators;
use namada_sdk::state::testing::TestState;
use namada_sdk::storage::{self, Key};
use namada_sdk::tx::data::TxType;
use namada_sdk::tx::{IndexedTx, Tx};
use namada_tx_prelude::BatchedTx;
use namada_vm::WasmCacheRwAccess;
use namada_vm::host_env::gas_meter::GasMeter;
use namada_vm::wasm::{self, VpCache};
use namada_vp_prelude::Ctx;
use tempfile::TempDir;

use crate::tx::{TestTxEnv, tx_host_env};

/// VP execution context provides access to host env functions
pub static CTX: Ctx = unsafe { Ctx::new() };

/// VP execution context provides access to host env functions
pub fn ctx() -> &'static Ctx {
    &CTX
}

/// Host environment for VP and integration tests.
///
/// This module combines the native host function implementations from
/// `native_vp_host_env` with the functions exposed to the vp wasm
/// that will call to the native functions, instead of interfacing via a
/// wasm runtime.
pub mod vp_host_env {
    pub use namada_vp_prelude::*;

    pub use super::ctx;
    pub use super::native_vp_host_env::*;
}

/// Host environment structures required for transactions.
#[derive(Debug)]
pub struct TestVpEnv {
    pub addr: Address,
    pub state: TestState,
    pub iterators: PrefixIterators<'static, MockDB>,
    pub gas_meter: RefCell<GasMeter<VpGasMeter>>,
    pub batched_tx: BatchedTx,
    pub indexed_tx: IndexedTx,
    pub keys_changed: BTreeSet<storage::Key>,
    pub verifiers: BTreeSet<Address>,
    pub eval_runner: native_vp_host_env::VpEval,
    pub result_buffer: Option<Vec<u8>>,
    pub yielded_value: Option<Vec<u8>>,
    pub vp_wasm_cache: VpCache<WasmCacheRwAccess>,
    pub vp_cache_dir: TempDir,
}

impl Default for TestVpEnv {
    fn default() -> Self {
        let eval_runner = wasm::run::VpEvalWasm::default();

        let (vp_wasm_cache, vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let state = TestState::default();
        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.push_default_inner_tx();
        let batched_tx = tx.batch_first_tx();
        Self {
            addr: address::testing::established_address_1(),
            state,
            iterators: PrefixIterators::default(),
            gas_meter: RefCell::new(GasMeter::Native(
                VpGasMeter::new_from_tx_meter(&TxGasMeter::new(
                    1_000_000_000_000,
                    1,
                )),
            )),
            batched_tx,
            indexed_tx: IndexedTx::default(),
            keys_changed: BTreeSet::default(),
            verifiers: BTreeSet::default(),
            eval_runner,
            result_buffer: None,
            yielded_value: None,
            vp_wasm_cache,
            vp_cache_dir,
        }
    }
}

impl TestVpEnv {
    pub fn all_touched_storage_keys(&self) -> BTreeSet<Key> {
        self.state.write_log().get_keys()
    }

    pub fn get_verifiers(&self) -> BTreeSet<Address> {
        self.state
            .write_log()
            .verifiers_and_changed_keys(&self.verifiers)
            .0
    }
}

/// This module allows to test code with vp host environment functions.
/// It keeps a thread-local global `VpEnv`, which is passed to any of
/// invoked host environment functions and so it must be initialized
/// before the test.
mod native_vp_host_env {
    use std::pin::Pin;

    // TODO replace with `std::concat_idents` once stabilized (https://github.com/rust-lang/rust/issues/29599)
    use concat_idents::concat_idents;
    use namada_sdk::state::StateRead;
    use namada_vm::host_env::*;

    use super::*;

    pub type VpEval = namada_vm::wasm::run::VpEvalWasm<
        <TestState as StateRead>::D,
        <TestState as StateRead>::H,
        WasmCacheRwAccess,
    >;

    thread_local! {
        /// A [`TestVpEnv`] that can be used for VP host env functions calls
        /// that implements the WASM host environment in native environment.
        pub static ENV: RefCell<Option<Pin<Box<TestVpEnv>>>> =
            const {RefCell::new(None) };
    }

    /// Initialize the VP environment in [`ENV`]. This will be used in the
    /// host env function calls via macro `native_host_fn!`.
    pub fn init() {
        ENV.with(|env| {
            let test_env = TestVpEnv::default();
            *env.borrow_mut() = Some(Box::pin(test_env));
        });
    }

    /// Set the VP host environment in [`ENV`] from the given [`TestVpEnv`].
    /// This will be used in the host env function calls via
    /// macro `native_host_fn!`.
    pub fn set(test_env: TestVpEnv) {
        ENV.with(|env| {
            *env.borrow_mut() = Some(Box::pin(test_env));
        });
    }

    /// Mutably borrow the [`TestVpEnv`] from [`ENV`]. The [`ENV`] must be
    /// initialized.
    pub fn with<T>(f: impl Fn(&mut TestVpEnv) -> T) -> T {
        ENV.with(|env| {
            let mut env = env.borrow_mut();
            let mut env = env
                .as_mut()
                .expect(
                    "Did you forget to initialize the ENV? (e.g. call to \
                     `vp_host_env::init()`)",
                )
                .as_mut();
            f(&mut env)
        })
    }

    /// Take the [`TestVpEnv`] out of [`ENV`]. The [`ENV`] must be initialized.
    pub fn take() -> TestVpEnv {
        ENV.with(|env| {
            let mut env = env.borrow_mut();
            let env = env.take().expect(
                "Did you forget to initialize the ENV? (e.g. call to \
                 `vp_host_env::init()`)",
            );
            let env = Pin::into_inner(env);
            *env
        })
    }

    /// Initialize the VP host environment in [`ENV`] by running a transaction.
    ///
    /// The transaction is expected to modify the storage sub-space of the given
    /// address `addr` or to add it to the set of verifiers using
    /// `ctx.insert_verifier`.
    pub fn init_from_tx(
        addr: Address,
        mut tx_env: TestTxEnv,
        mut apply_tx: impl FnMut(&Address),
    ) {
        // Write an empty validity predicate for the address, because it's used
        // to check if the address exists when we write into its storage
        let vp_key = Key::validity_predicate(&addr);
        tx_env.state.db_write(&vp_key, vec![]).unwrap();

        tx_host_env::set(tx_env);
        apply_tx(&addr);

        let tx_env = tx_host_env::take();
        let verifiers_from_tx = &tx_env.verifiers;
        let (verifiers, keys_changed) = tx_env
            .state
            .write_log()
            .verifiers_and_changed_keys(verifiers_from_tx);
        if !verifiers.contains(&addr) {
            panic!(
                "The VP for the given address has not been triggered by the \
                 transaction, {:#?}",
                keys_changed
            );
        }

        let vp_env = TestVpEnv {
            addr,
            state: tx_env.state,
            keys_changed,
            verifiers,
            ..Default::default()
        };

        set(vp_env);
    }

    /// A helper macro to create implementations of the host environment
    /// functions exported to wasm, which uses the environment from the
    /// `ENV` variable.
    macro_rules! native_host_fn {
            // unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) ) => {
                concat_idents!(extern_fn_name = namada, _, $fn {
                    #[unsafe(no_mangle)]
                    extern "C-unwind" fn extern_fn_name( $($arg: $type),* ) {
                        with(|TestVpEnv {
                                addr,
                                state,
                                iterators,
                                gas_meter,
                                batched_tx,
                                indexed_tx,
                                keys_changed,
                                verifiers,
                                eval_runner,
                                result_buffer,
                                yielded_value,
                                vp_wasm_cache,
                                vp_cache_dir: _,
                            }: &mut TestVpEnv| {

                            let mut env = namada_vm::host_env::testing::vp_env(
                                addr,
                                state,
                                iterators,
                                gas_meter,
                                &batched_tx.tx,
                                &batched_tx.cmt,
                                indexed_tx,
                                verifiers,
                                result_buffer,
                                yielded_value,
                                keys_changed,
                                eval_runner,
                                vp_wasm_cache,
                            );

                            // Call the `host_env` function and unwrap any
                            // runtime errors
                            $fn( &mut env, $($arg),* ).unwrap()
                        })
                    }
                });
            };

            // non-unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty ) => {
                concat_idents!(extern_fn_name = namada, _, $fn {
                    #[unsafe(no_mangle)]
                    extern "C-unwind" fn extern_fn_name( $($arg: $type),* ) -> $ret {
                        with(|TestVpEnv {
                                addr,
                                state,
                                iterators,
                                gas_meter,
                                batched_tx,
                                indexed_tx,
                                keys_changed,
                                verifiers,
                                eval_runner,
                                result_buffer,
                                yielded_value,
                                vp_wasm_cache,
                                vp_cache_dir: _,
                            }: &mut TestVpEnv| {

                            let mut env = namada_vm::host_env::testing::vp_env(
                                addr,
                                state,
                                iterators,
                                gas_meter,
                                &batched_tx.tx,
                                &batched_tx.cmt,
                                indexed_tx,
                                verifiers,
                                result_buffer,
                                yielded_value,
                                keys_changed,
                                eval_runner,
                                vp_wasm_cache,
                            );

                            // Call the `host_env` function and unwrap any
                            // runtime errors
                            $fn( &mut env, $($arg),* ).unwrap()
                        })
                    }
                });
            }
        }

    // Implement all the exported functions from
    // [`namada_vm_env::imports::vp`] `extern "C"` section.
    native_host_fn!(vp_read_pre(key_ptr: u64, key_len: u64) -> i64);
    native_host_fn!(vp_read_post(key_ptr: u64, key_len: u64) -> i64);
    native_host_fn!(vp_read_temp(key_ptr: u64, key_len: u64) -> i64);
    native_host_fn!(vp_result_buffer(result_ptr: u64));
    native_host_fn!(vp_has_key_pre(key_ptr: u64, key_len: u64) -> i64);
    native_host_fn!(vp_has_key_post(key_ptr: u64, key_len: u64) -> i64);
    native_host_fn!(vp_iter_prefix_pre(prefix_ptr: u64, prefix_len: u64) -> u64);
    native_host_fn!(vp_iter_prefix_post(prefix_ptr: u64, prefix_len: u64) -> u64);
    native_host_fn!(vp_iter_next(iter_id: u64) -> i64);
    native_host_fn!(vp_get_chain_id(result_ptr: u64));
    native_host_fn!(vp_get_block_height() -> u64);
    native_host_fn!(vp_get_tx_index() -> u32);
    native_host_fn!(vp_get_block_header(height: u64) -> i64);
    native_host_fn!(vp_get_tx_code_hash(result_ptr: u64));
    native_host_fn!(vp_get_block_epoch() -> u64);
    native_host_fn!(vp_get_pred_epochs() -> i64);
    native_host_fn!(vp_get_native_token(result_ptr: u64));
    native_host_fn!(vp_eval(
            vp_code_ptr: u64,
            vp_code_len: u64,
            input_data_ptr: u64,
            input_data_len: u64,
        ) -> i64);
    native_host_fn!(vp_log_string(str_ptr: u64, str_len: u64));
    native_host_fn!(vp_verify_tx_section_signature(
        hash_list_ptr: u64,
        hash_list_len: u64,
        public_keys_map_ptr: u64,
        public_keys_map_len: u64,
        signer_ptr: u64,
        signer_len: u64,
        threshold: u8,
    ));
    native_host_fn!(vp_charge_gas(used_gas: u64));
    native_host_fn!(vp_yield_value(buf_ptr: u64, buf_len: u64));
}
