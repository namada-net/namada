//! Namada integrations and WASM tests and testing helpers.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

mod vm_host_env;
pub use vm_host_env::{tx, vp};
#[cfg(test)]
mod e2e;
#[cfg(test)]
pub mod hw_wallet_automation;
#[cfg(test)]
mod integration;
pub mod native_vp;
pub mod storage;
#[cfg(test)]
mod storage_api;
#[cfg(test)]
pub mod strings;

/// Using this import requires `tracing` and `tracing-subscriber` dependencies.
/// Set env var `RUST_LOG=info` to see the logs from a test run (and
/// `--nocapture` if the test is not failing).
pub mod log {
    pub use test_log::test;
}

pub use namada_sdk::*;

/// A type corresponding to cometbft `FilePVLastSignState` in `privval/file.go`
/// stored in `cometbft/data/priv_validator_state.json`
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[cfg(test)]
struct LastSignState {
    // i64 encoded as a string
    pub height: String,
    pub round: i32,
    pub step: i8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signbytes: Option<String>,
}

#[test]
fn test_last_sign_state_encoding() {
    // An example taken from `cometbft/data/priv_validate_state.json`
    let example_state = serde_json::json!({
      "height": "36",
      "round": 0,
      "step": 3,
      "signature": "pBNefaWQtXBKXGCmiwdz3SVifEoytgoRD/Ui0JiA7giZYTwInKcLITyZLVHnZ/nbKq8CULoMrLhasAHPsS6HAw==",
      "signbytes": "8301080211240000000000000022480A202B35C46A53F9E93AC38BDF7CAC71CAEBEC3889308BBB6012D848A67FE1756923122408011220530C5626D32F9D0D95E8494396BD510560357439BBC7B2F2F689E1246281A9C72A0C08DCE5EDB50610D2AAABCC03321E6532652D746573742E336636616131326538323736346261613631376637"
    });

    let state: LastSignState = serde_json::from_value(example_state).unwrap();
    assert_eq!(&state.height, "36");
    assert_eq!(state.round, 0);
    assert_eq!(state.step, 3);
}
