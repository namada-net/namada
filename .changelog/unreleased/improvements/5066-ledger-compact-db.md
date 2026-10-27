- Added a `namadan ledger compact-db` command to compact the DB while the
  ledger is not running. It compacts the diffs column family by default, or
  every column family with `--all-column-families`.
  ([\#5066](https://github.com/namada-net/namada/pull/5066))
