- Fixed the quadratic section hashing over batch commitments, and the
  repeated lookups of inner transaction sections in native VPs, which
  made validation of large transaction batches unnecessarily slow. The
  transaction code hash is now also cached for VP `get_tx_code_hash`
  calls, and the mempool rejects wrappers with more than 100 inner
  transactions as defense in depth (a local policy that does not affect
  consensus).
  ([\#5050](https://github.com/namada-net/namada/pull/5050))
