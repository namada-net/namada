//! Utilities for use in tests.

pub mod ibc;
pub mod tx_data;

use std::env;
use std::path::PathBuf;

use strum::EnumIter;

/// Path from the root of the Git repo to the directory under which built test
/// wasms can be found.
pub const WASM_FOR_TESTS_DIR: &str = "wasm_for_tests";

/// Corresponds to wasms that we build for tests, under [`WASM_FOR_TESTS_DIR`].
/// See the `wasm_for_tests/wasm_source` crate for documentation on what these
/// wasms do.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, EnumIter)]
pub enum TestWasms {
    TxFail,
    TxFailEvent,
    TxMemoryLimit,
    TxNoOp,
    TxNoOpEvent,
    TxInvalidData,
    TxInfiniteGuestGas,
    TxInfiniteHostGas,
    TxProposalCode,
    TxProposalMaspRewards,
    TxProposalIbcTokenInflation,
    TxProposalIbcUnlimitedChannel,
    TxProposalTokenGas,
    TxReadStorageKey,
    TxWriteStorageKey,
    VpAlwaysFalse,
    VpAlwaysTrue,
    VpEval,
    VpInfiniteGuestGas,
    VpInfiniteHostGas,
    VpMemoryLimit,
    VpReadStorageKey,
    VpVerifySignature,
}

impl TestWasms {
    /// Get the path to where this test wasm is expected to be, or panic if not
    /// able to.
    pub fn path(&self) -> PathBuf {
        let filename = match self {
            TestWasms::TxFail => "tx_fail.wasm",
            TestWasms::TxFailEvent => "tx_fail_event.wasm",
            TestWasms::TxMemoryLimit => "tx_memory_limit.wasm",
            TestWasms::TxNoOp => "tx_no_op.wasm",
            TestWasms::TxNoOpEvent => "tx_no_op_event.wasm",
            TestWasms::TxInvalidData => "tx_invalid_data.wasm",
            TestWasms::TxInfiniteGuestGas => "tx_infinite_guest_gas.wasm",
            TestWasms::TxInfiniteHostGas => "tx_infinite_host_gas.wasm",
            TestWasms::TxProposalCode => "tx_proposal_code.wasm",
            TestWasms::TxProposalMaspRewards => "tx_proposal_masp_reward.wasm",
            TestWasms::TxProposalIbcTokenInflation => {
                "tx_proposal_ibc_token_inflation.wasm"
            }
            TestWasms::TxProposalIbcUnlimitedChannel => {
                "tx_proposal_ibc_unlimited_channel.wasm"
            }
            TestWasms::TxProposalTokenGas => "tx_proposal_token_gas.wasm",
            TestWasms::TxReadStorageKey => "tx_read_storage_key.wasm",
            TestWasms::TxWriteStorageKey => "tx_write.wasm",
            TestWasms::VpAlwaysFalse => "vp_always_false.wasm",
            TestWasms::VpAlwaysTrue => "vp_always_true.wasm",
            TestWasms::VpEval => "vp_eval.wasm",
            TestWasms::VpInfiniteGuestGas => "vp_infinite_guest_gas.wasm",
            TestWasms::VpInfiniteHostGas => "vp_infinite_host_gas.wasm",
            TestWasms::VpMemoryLimit => "vp_memory_limit.wasm",
            TestWasms::VpReadStorageKey => "vp_read_storage_key.wasm",
            TestWasms::VpVerifySignature => "vp_verify_signature.wasm",
        };
        let cwd =
            env::current_dir().expect("Couldn't get current working directory");
        // crudely find the root of the repo, we can't rely on the `.git`
        // directory being present, so look instead for the presence of a
        // CHANGELOG.md file
        let repo_root = cwd
            .ancestors()
            .find(|path| path.join("CHANGELOG.md").exists())
            .unwrap_or_else(|| {
                panic!(
                    "Couldn't find the root of the repository for the current \
                     working directory {}",
                    cwd.to_string_lossy()
                )
            });
        repo_root.join(WASM_FOR_TESTS_DIR).join(filename)
    }

    /// Attempts to read the contents of this test wasm. Panics if it is not
    /// able to for any reason.
    pub fn read_bytes(&self) -> Vec<u8> {
        let path = self.path();
        std::fs::read(&path).unwrap_or_else(|err| {
            panic!(
                "Could not read wasm at path {}: {:?}",
                path.to_string_lossy(),
                err
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::*;

    #[test]
    /// Tests that all expected test wasms are present on disk.
    fn test_wasms_path() {
        for test_wasm in TestWasms::iter() {
            let path = test_wasm.path();
            assert!(path.exists());
        }
    }
}
