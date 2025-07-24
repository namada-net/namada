//! The wasm host environment.
//!
//! Here, we expose the host functions into wasm's
//! imports, so they can be called from inside the wasm.

use namada_state::{DB, DBIter, StorageHasher};
use wasmer::{Function, FunctionEnv, Imports};

use crate::host_env::{TxVmEnv, VpEvaluator, VpVmEnv};
use crate::wasm::memory::WasmMemory;
use crate::{WasmCacheAccess, host_env};

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// transaction code
#[allow(clippy::too_many_arguments)]
pub fn tx_imports<D, H, CA>(
    wasm_store: &mut impl wasmer::AsStoreMut,
    env: TxVmEnv<WasmMemory, D, H, CA>,
) -> Imports
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
    CA: WasmCacheAccess + 'static,
{
    let env = FunctionEnv::new(wasm_store, env);

    wasmer::imports! {
        // Default namespace
        "env" => {
            // Gas injection hook
            "gas" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_1(host_env::tx_charge_gas)),
            // Tx Host functions
            "namada_tx_delete" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_delete)),
            "namada_tx_emit_event" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_emit_event)),
            "namada_tx_get_block_epoch" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_0(host_env::tx_get_block_epoch)),
            "namada_tx_get_block_header" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_1(host_env::tx_get_block_header)),
            "namada_tx_get_block_height" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_0(host_env::tx_get_block_height)),
            "namada_tx_get_chain_id" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_1(host_env::tx_get_chain_id)),
            "namada_tx_get_events" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_get_events)),
            "namada_tx_get_native_token" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_1(host_env::tx_get_native_token)),
            "namada_tx_get_pred_epochs" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_0(host_env::tx_get_pred_epochs)),
            "namada_tx_get_tx_index" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_0(host_env::tx_get_tx_index)),
            "namada_tx_has_key" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_has_key)),
            "namada_tx_init_account" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_7(host_env::tx_init_account)),
            "namada_tx_insert_verifier" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_insert_verifier)),
            "namada_tx_iter_next" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_1(host_env::tx_iter_next)),
            "namada_tx_iter_prefix" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_iter_prefix)),
            "namada_tx_log_string" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_log_string)),
            "namada_tx_read" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_read)),
            "namada_tx_read_temp" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_read_temp)),
            "namada_tx_result_buffer" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_1(host_env::tx_result_buffer)),
            "namada_tx_set_commitment_sentinel" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_0(host_env::tx_set_commitment_sentinel)),
            "namada_tx_update_masp_note_commitment_tree" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_update_masp_note_commitment_tree)),
            "namada_tx_update_validity_predicate" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_6(host_env::tx_update_validity_predicate)),
            "namada_tx_verify_tx_section_signature" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_5(host_env::tx_verify_tx_section_signature)),
            "namada_tx_write" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_4(host_env::tx_write)),
            "namada_tx_write_temp" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_4(host_env::tx_write_temp)),
            "namada_tx_yield_value" => Function::new_typed_with_env(wasm_store, &env, wrap_tx::_2(host_env::tx_yield_value)),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
pub fn vp_imports<D, H, EVAL, CA>(
    wasm_store: &mut impl wasmer::AsStoreMut,
    env: VpVmEnv<WasmMemory, D, H, EVAL, CA>,
) -> Imports
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
    EVAL: VpEvaluator<Db = D, H = H, Eval = EVAL, CA = CA> + 'static,
    CA: WasmCacheAccess + 'static,
{
    let env = FunctionEnv::new(wasm_store, env);

    wasmer::imports! {
        // Default namespace
        "env" => {
            // Gas injection hook
            "gas" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_1(host_env::vp_charge_gas)),
            // VP Host functions
            "namada_vp_eval" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_4(host_env::vp_eval)),
            "namada_vp_get_block_header" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_1(host_env::vp_get_block_header)),
            "namada_vp_get_block_height" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_0(host_env::vp_get_block_height)),
            "namada_vp_get_chain_id" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_1(host_env::vp_get_chain_id)),
            "namada_vp_get_events" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_2(host_env::vp_get_events)),
            "namada_vp_get_native_token" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_1(host_env::vp_get_native_token)),
            "namada_vp_get_pred_epochs" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_0(host_env::vp_get_pred_epochs)),
            "namada_vp_get_tx_code_hash" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_1(host_env::vp_get_tx_code_hash)),
            "namada_vp_get_tx_index" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_0(host_env::vp_get_tx_index)),
            "namada_vp_has_key_post" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_2(host_env::vp_has_key_post)),
            "namada_vp_has_key_pre" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_2(host_env::vp_has_key_pre)),
            "namada_vp_iter_next" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_1(host_env::vp_iter_next)),
            "namada_vp_iter_prefix_post" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_2(host_env::vp_iter_prefix_post)),
            "namada_vp_iter_prefix_pre" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_2(host_env::vp_iter_prefix_pre)),
            "namada_vp_log_string" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_2(host_env::vp_log_string)),
            "namada_vp_read_post" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_2(host_env::vp_read_post)),
            "namada_vp_read_pre" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_2(host_env::vp_read_pre)),
            "namada_vp_read_temp" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_2(host_env::vp_read_temp)),
            "namada_vp_result_buffer" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_1(host_env::vp_result_buffer)),
            "namada_vp_verify_tx_section_signature" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_7(host_env::vp_verify_tx_section_signature)),
            "namada_vp_verify_signature" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_4(host_env::vp_verify_signature)),
            "namada_vp_yield_value" => Function::new_typed_with_env(wasm_store, &env, wrap_vp::_2(host_env::vp_yield_value)),
        },
    }
}

// TODO(namada#3313): Attempt to reduce the boilerplate of this module with
// macros, traits or something of this sort...
mod wrap_tx {
    //! Wrap tx host functions with any number of arguments in a callback
    //! that can be passed to [`wasmer`], to be used by the guest wasm code.

    #![allow(missing_docs)]
    #![allow(clippy::type_complexity)]

    use namada_state::{DB, DBIter, StorageHasher};
    use wasmer::FunctionEnvMut;

    use crate::WasmCacheAccess;
    use crate::host_env::TxVmEnv;
    use crate::wasm::memory::WasmMemory;

    pub(super) fn _0<F, RET, D, H, CA>(
        f: F,
    ) -> impl Fn(FunctionEnvMut<'_, TxVmEnv<WasmMemory, D, H, CA>>) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        F: Fn(&mut TxVmEnv<WasmMemory, D, H, CA>) -> RET,
    {
        move |mut env| f(env.data_mut())
    }

    pub(super) fn _1<F, ARG0, RET, D, H, CA>(
        f: F,
    ) -> impl Fn(FunctionEnvMut<'_, TxVmEnv<WasmMemory, D, H, CA>>, ARG0) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        F: Fn(&mut TxVmEnv<WasmMemory, D, H, CA>, ARG0) -> RET,
    {
        move |mut env, arg0| f(env.data_mut(), arg0)
    }

    pub(super) fn _2<F, ARG0, ARG1, RET, D, H, CA>(
        f: F,
    ) -> impl Fn(FunctionEnvMut<'_, TxVmEnv<WasmMemory, D, H, CA>>, ARG0, ARG1) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        F: Fn(&mut TxVmEnv<WasmMemory, D, H, CA>, ARG0, ARG1) -> RET,
    {
        move |mut env, arg0, arg1| f(env.data_mut(), arg0, arg1)
    }

    pub(super) fn _4<F, ARG0, ARG1, ARG2, ARG3, RET, D, H, CA>(
        f: F,
    ) -> impl Fn(
        FunctionEnvMut<'_, TxVmEnv<WasmMemory, D, H, CA>>,
        ARG0,
        ARG1,
        ARG2,
        ARG3,
    ) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        F: Fn(
            &mut TxVmEnv<WasmMemory, D, H, CA>,
            ARG0,
            ARG1,
            ARG2,
            ARG3,
        ) -> RET,
    {
        move |mut env, arg0, arg1, arg2, arg3| {
            f(env.data_mut(), arg0, arg1, arg2, arg3)
        }
    }

    pub(super) fn _5<F, ARG0, ARG1, ARG2, ARG3, ARG4, RET, D, H, CA>(
        f: F,
    ) -> impl Fn(
        FunctionEnvMut<'_, TxVmEnv<WasmMemory, D, H, CA>>,
        ARG0,
        ARG1,
        ARG2,
        ARG3,
        ARG4,
    ) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        F: Fn(
            &mut TxVmEnv<WasmMemory, D, H, CA>,
            ARG0,
            ARG1,
            ARG2,
            ARG3,
            ARG4,
        ) -> RET,
    {
        move |mut env, arg0, arg1, arg2, arg3, arg4| {
            f(env.data_mut(), arg0, arg1, arg2, arg3, arg4)
        }
    }

    pub(super) fn _6<F, ARG0, ARG1, ARG2, ARG3, ARG4, ARG5, RET, D, H, CA>(
        f: F,
    ) -> impl Fn(
        FunctionEnvMut<'_, TxVmEnv<WasmMemory, D, H, CA>>,
        ARG0,
        ARG1,
        ARG2,
        ARG3,
        ARG4,
        ARG5,
    ) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        F: Fn(
            &mut TxVmEnv<WasmMemory, D, H, CA>,
            ARG0,
            ARG1,
            ARG2,
            ARG3,
            ARG4,
            ARG5,
        ) -> RET,
    {
        move |mut env, arg0, arg1, arg2, arg3, arg4, arg5| {
            f(env.data_mut(), arg0, arg1, arg2, arg3, arg4, arg5)
        }
    }

    pub(super) fn _7<
        F,
        ARG0,
        ARG1,
        ARG2,
        ARG3,
        ARG4,
        ARG5,
        ARG6,
        RET,
        D,
        H,
        CA,
    >(
        f: F,
    ) -> impl Fn(
        FunctionEnvMut<'_, TxVmEnv<WasmMemory, D, H, CA>>,
        ARG0,
        ARG1,
        ARG2,
        ARG3,
        ARG4,
        ARG5,
        ARG6,
    ) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        F: Fn(
            &mut TxVmEnv<WasmMemory, D, H, CA>,
            ARG0,
            ARG1,
            ARG2,
            ARG3,
            ARG4,
            ARG5,
            ARG6,
        ) -> RET,
    {
        move |mut env, arg0, arg1, arg2, arg3, arg4, arg5, arg6| {
            f(env.data_mut(), arg0, arg1, arg2, arg3, arg4, arg5, arg6)
        }
    }
}

// TODO(namada#3313): Attempt to reduce the boilerplate of this module with
// macros, traits or something of this sort...
mod wrap_vp {
    //! Wrap vp host functions with any number of arguments in a callback
    //! that can be passed to [`wasmer`], to be used by the guest wasm code.

    #![allow(missing_docs)]
    #![allow(clippy::type_complexity)]

    use namada_state::{DB, DBIter, StorageHasher};
    use wasmer::FunctionEnvMut;

    use crate::WasmCacheAccess;
    use crate::host_env::{VpEvaluator, VpVmEnv};
    use crate::wasm::memory::WasmMemory;

    pub(super) fn _0<F, RET, D, H, EVAL, CA>(
        f: F,
    ) -> impl Fn(FunctionEnvMut<'_, VpVmEnv<WasmMemory, D, H, EVAL, CA>>) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        EVAL: VpEvaluator<Db = D, H = H, Eval = EVAL, CA = CA> + 'static,
        F: Fn(&mut VpVmEnv<WasmMemory, D, H, EVAL, CA>) -> RET,
    {
        move |mut env| f(env.data_mut())
    }

    pub(super) fn _1<F, ARG0, RET, D, H, EVAL, CA>(
        f: F,
    ) -> impl Fn(FunctionEnvMut<'_, VpVmEnv<WasmMemory, D, H, EVAL, CA>>, ARG0) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        EVAL: VpEvaluator<Db = D, H = H, Eval = EVAL, CA = CA> + 'static,
        F: Fn(&mut VpVmEnv<WasmMemory, D, H, EVAL, CA>, ARG0) -> RET,
    {
        move |mut env, arg0| f(env.data_mut(), arg0)
    }

    pub(super) fn _2<F, ARG0, ARG1, RET, D, H, EVAL, CA>(
        f: F,
    ) -> impl Fn(
        FunctionEnvMut<'_, VpVmEnv<WasmMemory, D, H, EVAL, CA>>,
        ARG0,
        ARG1,
    ) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        EVAL: VpEvaluator<Db = D, H = H, Eval = EVAL, CA = CA> + 'static,
        F: Fn(&mut VpVmEnv<WasmMemory, D, H, EVAL, CA>, ARG0, ARG1) -> RET,
    {
        move |mut env, arg0, arg1| f(env.data_mut(), arg0, arg1)
    }

    pub(super) fn _4<F, ARG0, ARG1, ARG2, ARG3, RET, D, H, EVAL, CA>(
        f: F,
    ) -> impl Fn(
        FunctionEnvMut<'_, VpVmEnv<WasmMemory, D, H, EVAL, CA>>,
        ARG0,
        ARG1,
        ARG2,
        ARG3,
    ) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        EVAL: VpEvaluator<Db = D, H = H, Eval = EVAL, CA = CA> + 'static,
        F: Fn(
            &mut VpVmEnv<WasmMemory, D, H, EVAL, CA>,
            ARG0,
            ARG1,
            ARG2,
            ARG3,
        ) -> RET,
    {
        move |mut env, arg0, arg1, arg2, arg3| {
            f(env.data_mut(), arg0, arg1, arg2, arg3)
        }
    }

    pub(super) fn _7<
        F,
        ARG0,
        ARG1,
        ARG2,
        ARG3,
        ARG4,
        ARG5,
        ARG6,
        RET,
        D,
        H,
        EVAL,
        CA,
    >(
        f: F,
    ) -> impl Fn(
        FunctionEnvMut<'_, VpVmEnv<WasmMemory, D, H, EVAL, CA>>,
        ARG0,
        ARG1,
        ARG2,
        ARG3,
        ARG4,
        ARG5,
        ARG6,
    ) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        EVAL: VpEvaluator<Db = D, H = H, Eval = EVAL, CA = CA> + 'static,
        F: Fn(
            &mut VpVmEnv<WasmMemory, D, H, EVAL, CA>,
            ARG0,
            ARG1,
            ARG2,
            ARG3,
            ARG4,
            ARG5,
            ARG6,
        ) -> RET,
    {
        move |mut env, arg0, arg1, arg2, arg3, arg4, arg5, arg6| {
            f(env.data_mut(), arg0, arg1, arg2, arg3, arg4, arg5, arg6)
        }
    }

    pub(super) fn _9<
        F,
        ARG0,
        ARG1,
        ARG2,
        ARG3,
        ARG4,
        ARG5,
        ARG6,
        ARG7,
        ARG8,
        RET,
        D,
        H,
        EVAL,
        CA,
    >(
        f: F,
    ) -> impl Fn(
        FunctionEnvMut<'_, VpVmEnv<WasmMemory, D, H, EVAL, CA>>,
        ARG0,
        ARG1,
        ARG2,
        ARG3,
        ARG4,
        ARG5,
        ARG6,
        ARG7,
        ARG8,
    ) -> RET
    where
        D: DB + for<'iter> DBIter<'iter> + 'static,
        H: StorageHasher + 'static,
        CA: WasmCacheAccess + 'static,
        EVAL: VpEvaluator<Db = D, H = H, Eval = EVAL, CA = CA> + 'static,
        F: Fn(
            &mut VpVmEnv<WasmMemory, D, H, EVAL, CA>,
            ARG0,
            ARG1,
            ARG2,
            ARG3,
            ARG4,
            ARG5,
            ARG6,
            ARG7,
            ARG8,
        ) -> RET,
    {
        move |mut env, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8| {
            f(
                env.data_mut(),
                arg0,
                arg1,
                arg2,
                arg3,
                arg4,
                arg5,
                arg6,
                arg7,
                arg8,
            )
        }
    }
}
