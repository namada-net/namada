- Keep a share of the NOFILE limit out of RocksDB's reach so that a database
  with many SST files can no longer exhaust all file descriptors and crash the
  node with "Too many open files".
  ([\#5063](https://github.com/namada-net/namada/pull/5063))
