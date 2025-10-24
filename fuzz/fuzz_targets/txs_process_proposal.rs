#![no_main]

use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use namada_node::shell;
use namada_node::shell::test_utils::{ProcessProposal, TestShell};
use namada_tx::Tx;

lazy_static! {
    static ref SHELL: TestShell = {
        let (shell, _recv) = shell::test_utils::setup();
        shell
    };
}

fuzz_target!(|txs: Vec<Tx>| {
    let mut txs_bytes: Vec<Vec<u8>> = Vec::with_capacity(txs.len());
    for tx in txs {
        if let Ok(tx_bytes) = tx.try_to_bytes() {
            txs_bytes.push(tx_bytes);
        } else {
            return;
        }
    }

    let req = ProcessProposal { txs: txs_bytes };
    // An err means that the proposal was rejected, which is fine. We're only
    // looking for crashes here
    let _res = SHELL.process_proposal(req);
});
