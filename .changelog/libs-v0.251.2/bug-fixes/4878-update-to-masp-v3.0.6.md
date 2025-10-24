- Integrate an updated `nam-bellperson` that fixes issues in wasm,
  namely the usage of `std::time::Instant`, which has been replaced
  with `wasmtimer::std::Instant`. Moreover, silence a lot of the
  `INFO` log lines previously sent to the CLI, when generating proofs.
  ([\#4878](https://github.com/namada-net/namada/pull/4878))