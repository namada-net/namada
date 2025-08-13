use std::cell::RefCell;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use namada_apps_lib::{
    gas::{GasMeterKind, TxGasMeter},
    tx::{self, Tx, data::TxType},
};
use namada_test_utils::TestWasms;
use namada_vm::wasm;
use namada_vp::state::{TxIndex, testing::TestState};

fn tx_run(c: &mut Criterion) {
    let mut group = c.benchmark_group("wasm_run");
    let (mut tx_cache, _) = wasm::compilation_cache::common::testing::cache();
    let (mut vp_cache, _) = wasm::compilation_cache::common::testing::cache();

    let tx_index = TxIndex::default();
    let mut state = TestState::default();
    let gas_meter = RefCell::new(TxGasMeter::new(u64::MAX, 1));

    // Up to 4 MiB
    for data_size_pow in 1..22 {
        let tx_code = TestWasms::TxWriteStorageKey.read_bytes();
        let data_size = 2_usize.pow(data_size_pow);
        let tx_data: Vec<u8> = vec![6_u8; data_size];
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(tx::Code::new(tx_code, None));
        outer_tx.set_data(tx::Data::new(tx_data));
        let batched_tx = outer_tx.batch_ref_first_tx().unwrap();

        group.bench_function(
            BenchmarkId::new("wasm::run::tx", format!("{data_size_pow}")),
            |b| {
                b.iter(|| {
                    wasm::run::tx(
                        &mut state,
                        &gas_meter,
                        None,
                        &tx_index,
                        batched_tx.tx,
                        batched_tx.cmt,
                        &mut vp_cache,
                        &mut tx_cache,
                        GasMeterKind::MutGlobal,
                    )
                })
            },
        );
    }
}

criterion_group!(wasm_run, tx_run);
criterion_main!(wasm_run);
