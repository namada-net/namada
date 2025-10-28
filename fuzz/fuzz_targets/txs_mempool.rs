#![no_main]

use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use namada_node::shell;
use namada_node::shell::MempoolTxType;
use namada_node::shell::test_utils::TestShell;
use namada_tx::Tx;

lazy_static! {
    static ref SHELL: TestShell = shell::test_utils::setup();
}

fuzz_target!(|tx: Tx| {
    if let Ok(tx_bytes) = tx.try_to_bytes() {
        SHELL.mempool_validate(&tx_bytes, MempoolTxType::NewTransaction);
    }
});
